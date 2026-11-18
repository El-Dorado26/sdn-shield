#!/usr/bin/env bash
set -euo pipefail

mkdir -p /results
{
    uname -a
    ovs-vsctl --version
    mn --version
    unshare -n sh -ec '
        ip link add probe0 type veth peer name probe1
        ip link set probe0 up
        tc qdisc add dev probe0 root tbf rate 1mbit burst 16kb latency 50ms
        tc qdisc show dev probe0
    '
    # Container kernels can support OVS without exposing loadable modules.
    /usr/share/openvswitch/scripts/ovs-ctl --system-id=random --no-ovs-vswitchd start
    ovs-vswitchd --pidfile --detach --log-file
    ovs-vsctl add-br probe-br
    ovs-appctl dpif/show
    ovs-vsctl del-br probe-br
    /usr/bin/python3 -u /lab/network_smoke_test.py
} 2>&1 | tee /results/test.log
