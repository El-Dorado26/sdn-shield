use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::{frame, receive};

struct Switch {
    path: PathBuf,
    listener: UnixListener,
}

impl Switch {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(format!(
            "/tmp/sdn-shield-{}-{}.sock",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { path, listener }
    }

    fn command(&self, command: &str, arguments: &[&str]) -> Child {
        Command::new(env!("CARGO_BIN_EXE_sdn-shield-controller"))
            .arg(command)
            .arg(&self.path)
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn accept(&self, child: &mut Child) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok((mut stream, _)) = self.listener.accept() {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert_eq!(receive(&mut stream).0, 0);
                stream.write_all(&frame(0, 99, &[])).unwrap();
                return stream;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "management command exited before connecting"
            );
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("management socket connection timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Switch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn flow_stats(packets: u64, bytes: u64) -> Vec<u8> {
    let mut flow = vec![0; 56];
    flow[..2].copy_from_slice(&56u16.to_be_bytes());
    flow[12..14].copy_from_slice(&1u16.to_be_bytes());
    flow[24..32].copy_from_slice(&0x5344_4e00_0000_0001u64.to_be_bytes());
    flow[32..40].copy_from_slice(&packets.to_be_bytes());
    flow[40..48].copy_from_slice(&bytes.to_be_bytes());
    flow[48..52].copy_from_slice(&[0, 1, 0, 4]);
    flow
}

#[test]
fn stats_collects_multipart_counters_and_answers_echo() {
    let switch = Switch::new();
    let mut child = switch.command("stats", &[]);
    let mut stream = switch.accept(&mut child);
    let (kind, xid, request) = receive(&mut stream);
    assert_eq!(kind, 18);
    assert_eq!(&request[..2], &1u16.to_be_bytes());
    let mut first = vec![0, 1, 0, 1, 0, 0, 0, 0];
    first.extend(flow_stats(7, 700));
    stream.write_all(&frame(19, xid, &first)).unwrap();
    stream.write_all(&frame(2, 120, b"echo")).unwrap();
    assert_eq!(receive(&mut stream), (3, 120, b"echo".to_vec()));
    let mut last = vec![0, 1, 0, 0, 0, 0, 0, 0];
    last.extend(flow_stats(11, 1100));
    stream.write_all(&frame(19, xid, &last)).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 2);
    assert!(stdout.contains("packets=7 bytes=700"));
    assert!(stdout.contains("packets=11 bytes=1100"));
}

#[test]
fn drop_is_narrow_timed_and_waits_for_the_matching_barrier() {
    let switch = Switch::new();
    let mut child = switch.command("drop", &["1", "10.0.0.1", "10.0.0.8", "6"]);
    let mut stream = switch.accept(&mut child);
    let (kind, _, flow) = receive(&mut stream);
    assert_eq!(kind, 14);
    assert_eq!(&flow[..8], &0x5344_4e00_0000_0002u64.to_be_bytes());
    assert_eq!(&flow[18..24], &[0, 0, 0, 6, 0, 100]);
    for oxm in [
        vec![0x80, 0, 0, 4, 0, 0, 0, 1],
        vec![0x80, 0, 0x16, 4, 10, 0, 0, 1],
        vec![0x80, 0, 0x18, 4, 10, 0, 0, 8],
        vec![0x80, 0, 0x14, 1, 1],
        vec![0x80, 0, 0x26, 1, 8],
    ] {
        assert!(flow.windows(oxm.len()).any(|part| part == oxm));
    }
    let match_len = usize::from(u16::from_be_bytes([flow[42], flow[43]]));
    assert_eq!(
        flow.len(),
        40 + ((match_len + 7) & !7),
        "drop must contain no forwarding instructions"
    );
    let (kind, xid, _) = receive(&mut stream);
    assert_eq!(kind, 20);
    assert!(
        child.try_wait().unwrap().is_none(),
        "must wait for barrier acknowledgement"
    );
    stream.write_all(&frame(21, xid, &[])).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("DROP_BARRIER_ACK")
    );
}

#[test]
fn rejects_malformed_stats_without_panicking() {
    let mut short_entry = flow_stats(1, 100);
    short_entry[..2].copy_from_slice(&7u16.to_be_bytes());
    let mut short_match = flow_stats(1, 100);
    short_match[50..52].copy_from_slice(&2u16.to_be_bytes());
    let mut long_match = flow_stats(1, 100);
    long_match[50..52].copy_from_slice(&100u16.to_be_bytes());
    for entry in [short_entry, short_match, long_match, vec![0]] {
        let switch = Switch::new();
        let mut child = switch.command("stats", &[]);
        let mut stream = switch.accept(&mut child);
        let (_, xid, _) = receive(&mut stream);
        let mut first = vec![0, 1, 0, 1, 0, 0, 0, 0];
        first.extend(flow_stats(7, 700));
        stream.write_all(&frame(19, xid, &first)).unwrap();
        let mut reply = vec![0, 1, 0, 0, 0, 0, 0, 0];
        reply.extend(entry);
        stream.write_all(&frame(19, xid, &reply)).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "do not publish partial snapshots");
    }
}

#[test]
fn rejects_mismatched_transaction_ids() {
    for command in ["stats", "drop"] {
        let switch = Switch::new();
        let arguments: &[&str] = if command == "drop" {
            &["1", "10.0.0.1", "10.0.0.8", "6"]
        } else {
            &[]
        };
        let mut child = switch.command(command, arguments);
        let mut stream = switch.accept(&mut child);
        let (_, mut xid, _) = receive(&mut stream);
        let body = if command == "drop" {
            xid = receive(&mut stream).1;
            Vec::new()
        } else {
            vec![0, 1, 0, 0, 0, 0, 0, 0]
        };
        stream
            .write_all(&frame(
                if command == "drop" { 21 } else { 19 },
                xid + 1,
                &body,
            ))
            .unwrap();
        assert!(!child.wait_with_output().unwrap().status.success());
    }
}

#[test]
fn bounds_multipart_reply_count() {
    let switch = Switch::new();
    let mut child = switch.command("stats", &[]);
    let mut stream = switch.accept(&mut child);
    let (_, xid, _) = receive(&mut stream);
    for _ in 0..256 {
        stream
            .write_all(&frame(19, xid, &[0, 1, 0, 1, 0, 0, 0, 0]))
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn does_not_acknowledge_a_rule_rejected_by_the_switch() {
    let switch = Switch::new();
    let mut child = switch.command("drop", &["1", "10.0.0.1", "10.0.0.8", "6"]);
    let mut stream = switch.accept(&mut child);
    let (_, xid, _) = receive(&mut stream);
    assert_eq!(receive(&mut stream).0, 20);
    stream.write_all(&frame(1, xid, &[0, 3, 0, 0])).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Error"));
}

#[test]
fn rejects_unsafe_drop_arguments_before_connecting() {
    for arguments in [
        ["0", "10.0.0.1", "10.0.0.8", "6"],
        ["4294967295", "10.0.0.1", "10.0.0.8", "6"],
        ["1", "0.0.0.0", "10.0.0.8", "6"],
        ["1", "224.0.0.1", "10.0.0.8", "6"],
        ["1", "10.0.0.1", "10.0.0.8", "0"],
        ["1", "10.0.0.1", "10.0.0.8", "65536"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sdn-shield-controller"))
            .args(["drop", "/nonexistent/switch.mgmt"])
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid"));
    }
}
