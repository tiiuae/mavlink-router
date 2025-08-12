# Use ROS builder image just to get the build tools in place
FROM ghcr.io/tiiuae/fog-ros-baseimage-builder:sha-c04d413 AS builder

RUN apt update \
    && apt install -y --no-install-recommends \
        meson ninja \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

# If target architecture is x86_64 the meson setup shall set '-march' to use build for generic x86-64
#  instead of using possible instruction set extensions of native host cpu of the build machine
RUN amd64_fix=$([ "$(uname -m)" == "x86_64" ] && echo "-Dc_args='-march=x86-64' -Dcpp_args='-march=x86-64'" || echo ""); \
    meson setup --buildtype=release $amd64_fix -Dsystemdsystemunitdir=/usr/lib/systemd/system build . \
    && ninja -C build

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/fog-minimal-container-image:sha-aa15159 AS runtime

ENTRYPOINT ["/entrypoint.sh"]
CMD [""]

RUN mkdir -p /etc/mavlink-router

COPY conf /etc/mavlink-router
COPY entrypoint.sh /entrypoint.sh

WORKDIR /fog-drone

COPY --from=builder /build/build/src/mavlink-routerd /usr/bin

