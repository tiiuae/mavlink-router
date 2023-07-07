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
    python3-future python3-lxml git \
    build-essential libtool autoconf \
    pkg-config gcc g++ autotools-dev automake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN ./autogen.sh \
    && ./configure CFLAGS='-g -O2' --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib64 --prefix=/usr --disable-systemd \
    && make

#  ▲               runtime ──┐
#  └── build                 ▼

FROM builder-${TARGETARCH} as runtime

# Setup timezone
RUN echo 'Etc/UTC' > /etc/timezone \
    && ln -s /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get update && apt-get install -q -y tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fog-drone

COPY --from=builder /build/mavlink-routerd /usr/bin

RUN mkdir -p /etc/mavlink-router
COPY --from=builder /build/main.uart.conf /etc/mavlink-router
COPY --from=builder /build/main.eth.conf /etc/mavlink-router

ENTRYPOINT ["/usr/bin/mavlink-routerd"]
CMD [""]

