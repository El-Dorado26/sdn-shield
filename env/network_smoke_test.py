import argparse
import json
import subprocess
import time

from topology import build


def ovs(*args):
    return subprocess.check_output(args, text=True, timeout=10)


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
