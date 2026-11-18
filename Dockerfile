FROM rust:1.92.0-slim-bookworm AS controller-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/controller
COPY controller/ ./
RUN cargo test --locked && cargo build --release --locked

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 mininet openvswitch-switch openvswitch-testcontroller \
        iproute2 iputils-ping iperf3 kmod util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=controller-build /build/controller/target/release/sdn-shield-controller /usr/local/bin/
WORKDIR /lab
COPY topology.py ./
COPY env/network_smoke_test.py env/docker-entrypoint.sh ./
ENTRYPOINT ["timeout", "180", "bash", "/lab/docker-entrypoint.sh"]
