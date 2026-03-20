FROM swift:6.2-jammy AS build

WORKDIR /app
COPY . .

WORKDIR /app/CBStressWeb
RUN swift build -c release

FROM swift:6.2-jammy-slim

WORKDIR /app

COPY --from=build /app/CBStressWeb/.build/release/CBStressWeb /app/CBStressWeb
COPY --from=build /app/CBStressWeb/Public /app/Public
COPY --from=build /app/CBStressWeb/Resources /app/Resources

EXPOSE 8080

CMD ["/app/CBStressWeb", "serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
