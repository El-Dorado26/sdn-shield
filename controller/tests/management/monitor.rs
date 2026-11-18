use std::io::Write;
use std::process::Command;

use super::{Switch, flow_stats};
use crate::{frame, receive};

fn forwarding_stats(packets: u64, bytes: u64, age: u32) -> Vec<u8> {
    let mut flow = flow_stats(packets, bytes);
    flow.truncate(48);
    flow[4..8].copy_from_slice(&age.to_be_bytes());
    flow.extend_from_slice(&[0, 1, 0, 32, 0x80, 0, 0, 4, 0, 0, 0, 1]);
    flow.extend_from_slice(&[0x80, 0, 8, 6, 0, 0, 0, 0, 0, 1]);
    flow.extend_from_slice(&[0x80, 0, 6, 6, 0, 0, 0, 0, 0, 8]);
    flow[..2].copy_from_slice(&80u16.to_be_bytes());
    flow
}

#[test]
fn polls_periodically_and_alarms_without_sending_flow_mods() {
    let switch = Switch::new();
    let mut child = switch.command("monitor", &["10", "2", "10", "100"]);
    let mut stream = switch.accept(&mut child);
    for (age, packets) in [(10, 100), (11, 100), (12, 200)] {
        let (kind, xid, request) = receive(&mut stream);
        assert_eq!(kind, 18, "monitor must only send statistics requests");
        assert_eq!(&request[..2], &[0, 1]);
        let mut response = vec![0, 1, 0, 0, 0, 0, 0, 0];
        response.extend(forwarding_stats(packets, packets * 100, age));
        stream.write_all(&frame(19, xid, &response)).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(output.contains("mitigation=off"));
    let samples: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("SAMPLE "))
        .collect();
    assert_eq!(samples.len(), 2, "{output}");
    assert!(samples[0].contains("alarm=0"));
    assert!(samples[1].contains("alarm=1"));
    assert!(samples[1].contains("destination=00:00:00:00:00:08"));
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("THRESHOLD_ALARM "))
            .count(),
        1
    );
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("WINDOW_END "))
            .count(),
        2
    );
}

#[test]
fn rejects_invalid_monitor_arguments_before_connecting() {
    for arguments in [
        ["0", "2", "10", "100"],
        ["60001", "2", "10", "100"],
        ["1000", "0", "10", "100"],
        ["1000", "2", "NaN", "100"],
        ["1000", "2", "inf", "100"],
        ["1000", "2", "10", "-1"],
        ["1000", "2", "0", "100"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sdn-shield-controller"))
            .args(["monitor", "/nonexistent/switch.mgmt"])
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid"));
    }
}
