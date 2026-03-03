FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/stealth ./cmd/stealth
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/stealth-mcp ./cmd/stealth-mcp
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/semantic-mcp ./cmd/semantic-mcp
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/semantic ./cmd/semantic
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/labd ./cmd/labd
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/brwslab ./cmd/brwslab

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/ /app/

ENV STEALTH_ENGINE=native
ENV STEALTH_TLS_SPOOFING=true

EXPOSE 8080 8443 9090

ENTRYPOINT ["/app/stealth"]
CMD ["--help"]
