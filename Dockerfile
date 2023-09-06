# Use ROS builder image just to get the build tools in place
FROM ghcr.io/tiiuae/fog-ros-baseimage-builder:feat-multiarch-pkcs11 AS builder

RUN apt update \
    && apt install -y --no-install-recommends \
        meson ninja \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN meson setup --buildtype=release -Dsystemdsystemunitdir=/usr/lib/systemd/system build . \
    && ninja -C build && cp /build/build/src/mavlink-routerd /usr/bin

ENTRYPOINT ["/usr/bin/mavlink-routerd"]
CMD ["-c", "/etc/mavlink-router/main.conf"]

RUN mkdir -p /etc/mavlink-router

COPY conf /etc/mavlink-router

WORKDIR /fog-drone

