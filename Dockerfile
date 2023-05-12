# Use ROS builder image just to get the build tools in place
FROM ghcr.io/tiiuae/fog-ros-baseimage-builder:feat-multiarch-pkcs11 AS builder

# Setup timezone
RUN ln -s -f /usr/share/zoneinfo/Etc/UTC /etc/localtime

#RUN apt-get update && apt-get install -y --no-install-recommends \
#    python3-future python3-lxml git python3-pip \
#    build-essential libtool autoconf cmake \
#    pkg-config gcc g++ autotools-dev automake \
#    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    meson ninja \
    && rm -rf /var/lib/apt/lists/*

#RUN pip3 install ninja meson

WORKDIR /build

COPY . .

RUN meson setup --buildtype=release -Dsystemdsystemunitdir=/usr/lib/systemd/system build . \
    && ninja -C build

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/fog-minimal-container-image:sha-0b457dc AS runtime

ENTRYPOINT ["/usr/bin/mavlink-routerd"]
CMD ["-c", "/etc/mavlink-router/main.conf"]

RUN mkdir -p /etc/mavlink-router
COPY conf /etc/mavlink-router

# Setup timezone
RUN ln -s -f /usr/share/zoneinfo/Etc/UTC /etc/localtime

WORKDIR /fog-drone

COPY --from=builder /build/build/src/mavlink-routerd /usr/bin

