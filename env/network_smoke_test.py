import argparse
import json
import re
import subprocess
import time
from pathlib import Path

from events import EventLog
from topology import build


def ovs(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def stats():
    output = subprocess.check_output([
        "sdn-shield-controller", "stats", "/var/run/openvswitch/s1.mgmt",
    ], text=True, timeout=10)
    rows = []
    for line in output.splitlines():
        prefix, *parts = line.split()
        assert prefix == "FLOW_STATS", line
        fields = dict(part.split("=", 1) for part in parts)
        match = fields.pop("match")
        row = {key: int(value, 0) for key, value in fields.items()}
        row["match"] = dict(field.split("=", 1) for field in match.split(",") if field != "*")
        rows.append(row)
    return rows


def probe(host, destination):
    process = host.popen([
        "ping", "-n", "-c", "2", "-i", "0.2", "-W", "1", destination.IP(),
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=6)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode in (0, 1), stderr or stdout
    summary = re.search(r"(\d+) packets transmitted, (\d+) received", stdout)
    assert summary, stdout
    return {"sent": int(summary[1]), "received": int(summary[2]), "stdout": stdout}


def mitigation(net):
    blocked, normal, victim, switch = [net.get(name) for name in ("h1", "h5", "h8", "s1")]
    port = switch.ports[switch.connectionsTo(blocked)[0][0]]
    expected = {"in_port": str(port), "eth_src": blocked.MAC(), "eth_dst": victim.MAC()}
    timeout = 6
    out_dir = "/results" if Path("/results").is_dir() else "runs"
    events = EventLog(f"mitigation-{time.time_ns()}", out_dir=out_dir, config={
        "source": blocked.IP(), "destination": victim.IP(), "in_port": port, "timeout": timeout,
    })

    def forwarding(rows):
        matches = [row for row in rows if row["cookie"] == 0x53444E0000000001
                   and row["priority"] == 1 and row["match"] == expected]
        assert len(matches) == 1, matches
        return matches[0]

    try:
        before = stats()
        baseline = forwarding(before)
        events.log("flow_stats", phase="before", flows=before)
        result = probe(blocked, victim)
        events.log("baseline_probe", **result)
        assert result["sent"] == result["received"] == 2, result
        deadline = time.monotonic() + 3
        while True:
            after = stats()
            current = forwarding(after)
            if current["packets"] > baseline["packets"] and current["bytes"] > baseline["bytes"]:
                break
            assert time.monotonic() < deadline, "Rust did not observe increasing counters"
            time.sleep(0.1)
        assert current["packets"] < 2**64 - 1 and current["bytes"] < 2**64 - 1
        assert (current["duration_sec"], current["duration_nsec"]) >= (baseline["duration_sec"], baseline["duration_nsec"]), "Flow reset during counter check"
        events.log("flow_stats", phase="after_traffic", flows=after)
        print("PASS: Rust flow packet/byte counters increased", flush=True)

        requested = time.monotonic()
        events.log("drop_requested")
        ack = subprocess.check_output([
            "sdn-shield-controller", "drop", "/var/run/openvswitch/s1.mgmt",
            str(port), blocked.IP(), victim.IP(), str(timeout),
        ], text=True, timeout=10)
        assert ack.startswith("DROP_BARRIER_ACK "), ack
        events.log("drop_barrier_ack", reply=ack.strip())
        result = probe(blocked, victim)
        events.log("drop_probe", elapsed_since_request=time.monotonic() - requested, **result)
        assert result["sent"] == 2 and result["received"] == 0, result
        print("PASS: timed drop observed in the data plane (0/2 received)", flush=True)

        result = probe(normal, victim)
        events.log("legitimate_probe", **result)
        assert result["sent"] == result["received"] == 2, result
        during = stats()
        dropped = [row for row in during if row["cookie"] == 0x53444E0000000002]
        assert len(dropped) == 1, dropped
        assert dropped[0]["priority"] == 100 and dropped[0]["hard_timeout"] == timeout and dropped[0]["idle_timeout"] == 0, dropped
        assert dropped[0]["match"] == {
            "in_port": str(port), "eth_type": "0x0800", "ip_proto": "1",
            "ipv4_src": blocked.IP(), "ipv4_dst": victim.IP(), "icmp_type": "8",
        }, dropped
        assert 2 <= dropped[0]["packets"] < 2**64 - 1 and 0 < dropped[0]["bytes"] < 2**64 - 1, dropped
        events.log("flow_stats", phase="during_drop", flows=during)
        print("PASS: legitimate client unaffected and drop counters increased", flush=True)

        deadline = requested + timeout + 4
        while True:
            recovered = stats()
            if not any(row["cookie"] == 0x53444E0000000002 for row in recovered):
                break
            assert time.monotonic() < deadline, "Timed drop rule did not expire"
            time.sleep(0.2)
        events.log("rule_expired")
        events.log("flow_stats", phase="after_expiry", flows=recovered)
        result = probe(blocked, victim)
        events.log("recovery_probe", **result)
        assert result["sent"] == result["received"] == 2, result
        events.log("test_result", success=True)
        print("PASS: drop expired without deletion; connectivity recovered (2/2 received)", flush=True)
        print("Mitigation events:", events.path, flush=True)
    except Exception as exc:
        events.log("test_result", success=False, error=str(exc))
        raise
    finally:
        events.close()


parser = argparse.ArgumentParser()
parser.add_argument("--controller", choices=("rust", "ovs"), default="rust")
args = parser.parse_args()

net = None
controller = None
server = None
try:
    net = build("127.0.0.1", 6653, 1)
    client, victim = net.get("h5"), net.get("h8")
    for host in net.hosts:
        assert not host.cmd("ip route show default").strip(), host.name
        links = json.loads(host.cmd("ip -j link show"))
        interfaces = {link["ifname"] for link in links if "UP" in link["flags"]}
        assert interfaces == {"lo", host.name + "-eth0"}, interfaces
    print("PASS: eight hosts have no default route or active external interfaces", flush=True)
    print("Link qdisc:", client.cmd("tc qdisc show dev h5-eth0"), flush=True)

    ovs("ovs-vsctl", "del-controller", "s1")
    ovs("ovs-vsctl", "set-fail-mode", "s1", "secure")
    ovs("ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1")
    ovs("ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=0,actions=NORMAL")
    loss = net.pingAll(timeout="1")
    assert loss == 0, f"Baseline packet loss: {loss}%"
    print("PASS: direct OVS forwarding, 56/56 probes received", flush=True)

    ovs("ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1")
    loss = net.ping(hosts=[client, victim], timeout="1")
    assert loss == 100, f"Traffic passed without controller or flows: {loss}% loss"
    print("PASS: negative control, no forwarding without controller/flows", flush=True)

    command = (["sdn-shield-controller"] if args.controller == "rust" else [
        "ovs-testcontroller", "-O", "OpenFlow13", "ptcp:6653:127.0.0.1",
        "--log-file=/tmp/controller.log",
    ])
    controller = subprocess.Popen(command)
    ovs("ovs-vsctl", "set-controller", "s1", "tcp:127.0.0.1:6653")
    deadline = time.monotonic() + 15
    while ovs("ovs-vsctl", "get", "Controller", "s1", "is_connected").strip() != "true":
        assert controller.poll() is None, "Controller exited unexpectedly"
        assert time.monotonic() < deadline, "Controller connection timed out"
        time.sleep(0.1)
    while "actions=CONTROLLER" not in ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"):
        assert controller.poll() is None, "Controller exited before installing the table-miss rule"
        assert time.monotonic() < deadline, "Controller setup timed out"
        time.sleep(0.1)
    loss = net.pingAll(timeout="1")
    assert loss == 0, f"Controller forwarding packet loss: {loss}%"
    flows = ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1")
    print(flows, flush=True)
    assert "priority=1" in flows and "NORMAL" not in flows, flows
    if args.controller == "rust":
        assert "cookie=0x53444e0000000001" in flows, flows
    print(f"PASS: {args.controller} OpenFlow 1.3 controller forwarding, 56/56 probes received", flush=True)

    server = victim.popen(["iperf3", "-s", "-1", "-B", victim.IP(), "-J"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 5
    while ":5201" not in victim.cmd("ss -ltn"):
        assert server.poll() is None, "iperf3 server exited unexpectedly"
        assert time.monotonic() < deadline, "iperf3 server startup timed out"
        time.sleep(0.1)
    traffic = client.popen(["iperf3", "-c", victim.IP(), "-t", "2", "-b", "500K", "-J"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = traffic.communicate(timeout=12)
    finally:
        if traffic.poll() is None:
            traffic.kill()
            traffic.wait()
    assert traffic.returncode == 0, stderr or stdout
    result = json.loads(stdout)
    assert "error" not in result, result
    received = result["end"]["sum_received"]
    assert received["bytes"] > 0, result
    server.wait(timeout=5)
    assert server.returncode == 0, server.stderr.read()
    assert controller.poll() is None, "Controller exited during the traffic test"
    print("PASS: bounded TCP transfer:", json.dumps(received), flush=True)
    if args.controller == "rust":
        mitigation(net)
        assert controller.poll() is None, "Controller exited during the mitigation test"
    print("ALL NETWORK SMOKE TESTS PASSED", flush=True)
finally:
    if server is not None and server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
    if net is not None:
        net.stop()
    if controller is not None:
        controller.terminate()
        controller.wait(timeout=5)
