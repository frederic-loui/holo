# Build image
# ==============================================================================

FROM ghcr.io/rust-lang/rust:nightly-bookworm AS build

RUN apt-get update && \
    apt-get install -y build-essential \
    cmake \
    libpcre2-dev \
    protobuf-compiler

ARG BUILD_PROFILE=release

WORKDIR /usr/src/holo
COPY . .
RUN cargo build --profile $BUILD_PROFILE

# Final base
# ==============================================================================

FROM ghcr.io/holo-routing/holo-cli:latest

RUN apt-get update && \
    apt-get install -y ifupdown \
    iputils-ping \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd -r holo
RUN useradd --system --shell /sbin/nologin --home-dir /var/run/holo/ -g holo holo
RUN mkdir -p /var/run/holo
RUN chown holo:holo /var/run/holo

RUN echo "alias holo-cli-show='holo-cli -c \"show state\"'" >> /root/.bashrc
RUN echo "alias ipr='ip -4 ro ; ip -6 ro ; ip -M ro'" >> /root/.bashrc

ARG BUILD_PROFILE=release
COPY --from=build /usr/src/holo/holo-daemon/holod.toml /etc/holod.toml
COPY --from=build /usr/src/holo/target/$BUILD_PROFILE/holod /usr/local/sbin/

ENV RUST_BACKTRACE=1
ENV RUST_LOG=holo=debug
ENTRYPOINT ["sh", "-c", "holod 2>> /tmp/holod.err"]
