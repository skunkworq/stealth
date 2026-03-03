FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /stealth ./cmd/stealth
RUN CGO_ENABLED=0 GOOS=linux go build -o /stealth-mcp ./cmd/stealth-mcp

FROM alpine:3.19

RUN apk add --no-cache ca-certificates chromium

WORKDIR /app

COPY --from=builder /stealth /app/stealth
COPY --from=builder /stealth-mcp /app/stealth-mcp
COPY --from=builder /app/config.yaml /app/config.yaml

ENV STEALTH_ENGINE=native
ENV STEALTH_TLS_SPOOFING=true

EXPOSE 9090

ENTRYPOINT ["/app/stealth"]
CMD ["--help"]
