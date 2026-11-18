use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rovs_openflow::{
    Flow, FlowStatsEntry, FlowStatsRequest, Match, Message, MessageType, OfError, Version,
};

use crate::{COOKIE, Result, read_message, send};

const DROP_COOKIE: u64 = COOKIE + 1;
const MAX_STATS_ENTRIES: usize = 16384;

fn connect(path: &str) -> Result<UnixStream> {
    if !Path::new(path).is_absolute() {
        return Err("invalid switch socket: expected an absolute Unix socket path".into());
    }
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    send(
        &mut stream,
        Message::new(Version::Of13, MessageType::Hello, 1, Default::default()),
    )?;
    if read_message(&mut stream)?.header.msg_type != MessageType::Hello {
        return Err("expected an OpenFlow 1.3 Hello from the management socket".into());
    }
    Ok(stream)
}

fn reply(stream: &mut UnixStream, kind: MessageType, xid: u32) -> Result<Message> {
    for _ in 0..64 {
        let message = read_message(stream)?;
        match message.header.msg_type {
            MessageType::EchoRequest => send(
                stream,
                Message::new(
                    Version::Of13,
                    MessageType::EchoReply,
                    message.header.xid,
                    message.body,
                ),
            )?,
            MessageType::Error => {
                return Err(rovs_openflow::Error::OfError(OfError::parse(&message.body)?).into());
            }
            actual if actual == kind && message.header.xid == xid => return Ok(message),
            _ => return Err("unexpected management reply type or transaction ID".into()),
        }
    }
    Err("management reply limit exceeded".into())
}

fn stats(stream: &mut UnixStream) -> Result<Vec<FlowStatsEntry>> {
    send(
        stream,
        FlowStatsRequest::new()
            .table(0)
            .to_message(Version::Of13, 2),
    )?;
    let mut entries = Vec::new();
    for _ in 0..256 {
        let message = reply(stream, MessageType::MultipartReply, 2)?;
        let body = &message.body;
        if body.len() < 8 || body[..2] != [0, 1] || body[2] != 0 || body[3] & !1 != 0 {
            return Err("invalid flow-statistics multipart header".into());
        }
        let mut offset = 8;
        while offset < body.len() {
            let remaining = &body[offset..];
            if remaining.len() < 56 || entries.len() >= MAX_STATS_ENTRIES {
                return Err("invalid or excessive flow-statistics entries".into());
            }
            let length = usize::from(u16::from_be_bytes([remaining[0], remaining[1]]));
            let match_len = usize::from(u16::from_be_bytes([remaining[50], remaining[51]]));
            // The library decoder assumes valid entry and padded match lengths.
            if length < 56
                || length > remaining.len()
                || length % 8 != 0
                || match_len < 4
                || 48 + ((match_len + 7) & !7) > length
            {
                return Err("invalid flow-statistics entry or match length".into());
            }
            let mut oxm = 52;
            let end = 48 + match_len;
            while oxm < end {
                if end - oxm < 4 {
                    return Err("invalid flow-statistics OXM header".into());
                }
                let size = usize::from(remaining[oxm + 3]);
                if size == 0
                    || oxm + 4 + size > end
                    || (remaining[oxm + 2] & 1 != 0 && size % 2 != 0)
                {
                    return Err("invalid flow-statistics OXM length".into());
                }
                oxm += 4 + size;
            }
            entries.push(FlowStatsEntry::decode(&remaining[..length])?.0);
            offset += length;
        }
        if body[3] & 1 == 0 {
            return Ok(entries);
        }
    }
    Err("flow-statistics multipart limit exceeded".into())
}

fn unicast(value: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = value.parse().map_err(|_| "invalid IPv4 address")?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("invalid drop address: expected a unicast IPv4 address".into());
    }
    Ok(ip)
}

pub fn run(args: &[String]) -> Result<()> {
    let (path, flow) =
        match args {
            [command, path] if command == "stats" => (path, None),
            [command, path, port, source, destination, seconds] if command == "drop" => {
                let port = port
                    .parse::<u32>()
                    .ok()
                    .filter(|port| *port > 0 && *port < 0xffff_ff00)
                    .ok_or("invalid ingress port")?;
                let seconds = seconds
                    .parse::<u16>()
                    .ok()
                    .filter(|seconds| *seconds > 0)
                    .ok_or("invalid timeout: expected 1..65535 seconds")?;
                let fields = Match::new()
                    .in_port(port)
                    .ipv4_src(unicast(source)?, 32)
                    .ipv4_dst(unicast(destination)?, 32)
                    .icmp_type(8);
                (
                    path,
                    Some(
                        Flow::add()
                            .cookie(DROP_COOKIE)
                            .priority(100)
                            .hard_timeout(seconds)
                            .match_fields(fields),
                    ),
                )
            }
            _ => return Err(
                "usage: stats SOCKET | drop SOCKET IN_PORT SOURCE_IPV4 DESTINATION_IPV4 SECONDS"
                    .into(),
            ),
        };
    let mut stream = connect(path)?;
    if let Some(flow) = flow {
        send(&mut stream, flow.to_message(Version::Of13, 2))?;
        send(
            &mut stream,
            Message::new(
                Version::Of13,
                MessageType::BarrierRequest,
                3,
                Default::default(),
            ),
        )?;
        if !reply(&mut stream, MessageType::BarrierReply, 3)?
            .body
            .is_empty()
        {
            return Err("invalid BarrierReply body".into());
        }
        println!(
            "DROP_BARRIER_ACK cookie={DROP_COOKIE:#x} timeout={} match={}",
            flow.hard_timeout, flow.match_fields
        );
    } else {
        for entry in stats(&mut stream)? {
            println!(
                "FLOW_STATS cookie={:#x} table={} priority={} packets={} bytes={} duration_sec={} duration_nsec={} idle_timeout={} hard_timeout={} match={}",
                entry.cookie,
                entry.table_id,
                entry.priority,
                entry.packet_count,
                entry.byte_count,
                entry.duration_sec,
                entry.duration_nsec,
                entry.idle_timeout,
                entry.hard_timeout,
                entry.match_fields
            );
        }
    }
    Ok(())
}
