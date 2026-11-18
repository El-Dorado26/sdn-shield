FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 mininet openvswitch-switch openvswitch-testcontroller \
        iproute2 iputils-ping iperf3 kmod util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY topology.py ./
COPY env/network_smoke_test.py env/docker-entrypoint.sh ./
ENTRYPOINT ["timeout", "180", "bash", "/lab/docker-entrypoint.sh"]
