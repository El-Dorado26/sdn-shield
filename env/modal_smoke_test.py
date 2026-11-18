# /// script
# requires-python = ">=3.10"
# dependencies = ["modal==1.6.4"]
# ///
"""Run with: uv run env/modal_smoke_test.py (requires Modal authentication)."""
from datetime import datetime, timezone
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
REMOTE_TEST = r'''
import json
import subprocess
import time

from topology import build


def ovs(*args):
    return subprocess.check_output(args, text=True, timeout=10)


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

    controller = subprocess.Popen([
        "ovs-testcontroller", "-O", "OpenFlow13", "ptcp:6653:127.0.0.1",
        "--log-file=/tmp/controller.log",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    ovs("ovs-vsctl", "set-controller", "s1", "tcp:127.0.0.1:6653")
    deadline = time.monotonic() + 15
    while ovs("ovs-vsctl", "get", "Controller", "s1", "is_connected").strip() != "true":
        assert controller.poll() is None, "Controller exited unexpectedly"
        assert time.monotonic() < deadline, "Controller connection timed out"
        time.sleep(0.1)
    loss = net.pingAll(timeout="1")
    assert loss == 0, f"Controller forwarding packet loss: {loss}%"
    flows = ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1")
    print(flows, flush=True)
    assert "actions=" in flows and "NORMAL" not in flows, flows
    print("PASS: OpenFlow 1.3 controller forwarding, 56/56 probes received", flush=True)

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
'''


def main():
    app = modal.App.lookup("sdn-shield-env-test", create_if_missing=True)
    image = (
        modal.Image.from_registry("ubuntu:22.04", add_python="3.11")
        .env({"DEBIAN_FRONTEND": "noninteractive"})
        .apt_install("mininet", "openvswitch-switch", "openvswitch-testcontroller",
                     "iproute2", "iputils-ping", "iperf3", "kmod")
        .add_local_file(ROOT / "topology.py", "/root/topology.py")
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ROOT / "runs" / f"modal-smoke-{stamp}"
    output.mkdir(parents=True)
    sandbox = None
    try:
        sandbox = modal.Sandbox.create(
            "sleep", "300", app=app, image=image, runtime="vm",
            block_network=True, cpu=2, memory=2048, timeout=300,
        )
        print("Sandbox:", sandbox.object_id, flush=True)
        (output / "sandbox.txt").write_text(sandbox.object_id + "\n")
        setup = sandbox.exec("bash", "-ec", """
            uname -a
            ovs-vsctl --version
            mn --version
            unshare -n sh -ec '
                ip link add probe0 type veth peer name probe1
                ip link set probe0 up
                tc qdisc add dev probe0 root tbf rate 1mbit burst 16kb latency 50ms
                tc qdisc show dev probe0
            '
            /usr/share/openvswitch/scripts/ovs-ctl --system-id=random start
        """, timeout=30)
        for name, stream in [("setup.stdout", setup.stdout), ("setup.stderr", setup.stderr)]:
            content = stream.read()
            (output / name).write_text(content)
            print(content, flush=True)
        setup.wait()
        if setup.returncode:
            raise SystemExit(setup.returncode)
        process = sandbox.exec("/usr/bin/python3", "-u", "-c", REMOTE_TEST,
                               workdir="/root", timeout=150)
        for name, stream in [("test.stdout", process.stdout), ("test.stderr", process.stderr)]:
            content = stream.read()
            (output / name).write_text(content)
            print(content, flush=True)
        process.wait()
        (output / "exit-code.txt").write_text(str(process.returncode) + "\n")
        if process.returncode:
            raise SystemExit(process.returncode)
    finally:
        if sandbox is not None:
            sandbox.terminate()
            print("Sandbox terminated", flush=True)
        print("Logs:", output, flush=True)


if __name__ == "__main__":
    main()
