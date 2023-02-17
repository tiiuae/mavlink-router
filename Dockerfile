#FROM ubuntu:20.04 as builder
FROM riscv64/ubuntu:20.04

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



#FROM ubuntu:20.04
FROM riscv64/ubuntu:20.04

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

