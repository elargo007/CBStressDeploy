# ================================
# Build image
# ================================
FROM swift:6.2.4-noble AS build

# Install OS updates + build dependency
RUN export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
    && apt-get -q update \
    && apt-get -q dist-upgrade -y \
    && apt-get install -y libjemalloc-dev \
    && rm -rf /var/lib/apt/lists/*

# Build root must contain all 3 sibling packages:
# /build/CBStressWeb
# /build/CBStressCore
# /build/CBStressReportKit
WORKDIR /build

# Copy manifests first for better layer caching
COPY ./CBStressWeb/Package.* ./CBStressWeb/
COPY ./CBStressCore/Package.* ./CBStressCore/
COPY ./CBStressReportKit/Package.* ./CBStressReportKit/

# Resolve from the web package root so local path deps work:
# ../CBStressCore
# ../CBStressReportKit
WORKDIR /build/CBStressWeb
RUN swift package resolve \
        $([ -f ./Package.resolved ] && echo "--force-resolved-versions" || true)

# Copy full source trees
WORKDIR /build
COPY ./CBStressWeb ./CBStressWeb
COPY ./CBStressCore ./CBStressCore
COPY ./CBStressReportKit ./CBStressReportKit

RUN mkdir /staging

# Build the application, with optimizations, static Swift stdlib, and jemalloc
WORKDIR /build/CBStressWeb
RUN --mount=type=cache,target=/build/CBStressWeb/.build \
    swift build -c release \
        --product CBStressWeb \
        --static-swift-stdlib \
        -Xlinker -ljemalloc && \
    BIN_PATH="$(swift build -c release --show-bin-path)" && \
    cp "$BIN_PATH/CBStressWeb" /staging && \
    find -L "$BIN_PATH" -regex '.*\.resources$' -exec cp -Ra {} /staging \; || true

# Switch to the staging area
WORKDIR /staging

# Copy static swift backtracer binary to staging area
RUN cp "/usr/libexec/swift/linux/swift-backtrace-static" ./

# Copy app resources if present
RUN [ -d /build/CBStressWeb/Public ] && { cp -Ra /build/CBStressWeb/Public ./Public && chmod -R a-w ./Public; } || true
RUN [ -d /build/CBStressWeb/Resources ] && { cp -Ra /build/CBStressWeb/Resources ./Resources && chmod -R a-w ./Resources; } || true

# ================================
# Run image
# ================================
FROM ubuntu:noble

# Install only essential runtime packages
RUN export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
    && apt-get -q update \
    && apt-get -q dist-upgrade -y \
    && apt-get -q install -y \
      libjemalloc2 \
      ca-certificates \
      tzdata \
    && rm -rf /var/lib/apt/lists/*

# Create vapor user/group
RUN useradd --user-group --create-home --system --skel /dev/null --home-dir /app vapor

# Switch to app directory
WORKDIR /app

# Copy built executable and staged resources
COPY --from=build --chown=vapor:vapor /staging /app

# Crash reporter / backtrace config
ENV SWIFT_BACKTRACE=enable=yes,sanitize=yes,threads=all,images=all,interactive=no,swift-backtrace=./swift-backtrace-static

# Run as non-root
USER vapor:vapor

# Vapor listens on 8080
EXPOSE 8080

# Start the Vapor service
ENTRYPOINT ["./CBStressWeb"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
