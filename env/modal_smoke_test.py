# /// script
# requires-python = ">=3.10"
# dependencies = ["modal==1.6.4"]
# ///
"""Run with: uv run env/modal_smoke_test.py (requires Modal authentication)."""
from datetime import datetime, timezone
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]


def main():
    app = modal.App.lookup("sdn-shield-env-test", create_if_missing=True)
    image = (
        modal.Image.from_registry("ubuntu:22.04", add_python="3.11")
        .env({"DEBIAN_FRONTEND": "noninteractive"})
        .apt_install("mininet", "openvswitch-switch", "openvswitch-testcontroller",
                     "iproute2", "iputils-ping", "iperf3", "kmod")
        .add_local_file(ROOT / "topology.py", "/root/topology.py")
        .add_local_file(ROOT / "env" / "network_smoke_test.py", "/root/network_smoke_test.py")
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
        process = sandbox.exec("/usr/bin/python3", "-u", "/root/network_smoke_test.py", "--controller", "ovs",
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
