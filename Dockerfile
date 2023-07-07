# Due to different naming convention, use this workaround
FROM ubuntu:22.04 as builder-amd64
FROM ubuntu:22.04 as builder-arm64
FROM riscv64/ubuntu:22.04 as builder-riscv64

FROM builder-${TARGETARCH} as builder

# Setup timezone
RUN echo 'Etc/UTC' > /etc/timezone \
    && ln -s /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get update && apt-get install -q -y tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-future python3-lxml git python3-pip \
    build-essential libtool autoconf \
    pkg-config gcc g++ autotools-dev automake \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install ninja meson

WORKDIR /build
COPY . .
RUN meson setup --buildtype=release -Dsystemdsystemunitdir=/usr/lib/systemd/system build . \
    && ninja -C build

#  ▲               runtime ──┐
#  └── build                 ▼

FROM builder-${TARGETARCH} as runtime

# Setup timezone
RUN echo 'Etc/UTC' > /etc/timezone \
    && ln -s /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get update && apt-get install -q -y tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fog-drone

COPY --from=builder /build/build/src/mavlink-routerd /usr/bin

RUN mkdir -p /etc/mavlink-router
COPY --from=builder /build/main.uart.conf /etc/mavlink-router
COPY --from=builder /build/main.eth.conf /etc/mavlink-router

ENTRYPOINT ["/usr/bin/mavlink-routerd"]
CMD [""]

