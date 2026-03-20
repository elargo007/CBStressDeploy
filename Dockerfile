FROM swift:6.2-jammy AS build

WORKDIR /app
COPY . .

WORKDIR /app/CBStressWeb
RUN swift build -c release

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libatomic1 \
    libcurl4 \
    libxml2 \
    libsqlite3-0 \
    libicu70 \
    tzdata \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/CBStressWeb/.build/release/CBStressWeb /app/CBStressWeb
COPY --from=build /app/CBStressWeb/Public /app/Public
COPY --from=build /app/CBStressWeb/Resources /app/Resources

EXPOSE 8080

CMD ["/app/CBStressWeb", "serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
