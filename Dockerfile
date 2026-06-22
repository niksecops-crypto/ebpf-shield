ARG VERSION=dev

FROM golang:1.22-alpine AS builder
ARG VERSION
RUN apk add --no-cache clang llvm libbpf-dev linux-headers make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make generate && \
    CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -s -w" -o /bin/shield ./cmd/shield

FROM gcr.io/distroless/base-debian12:latest
COPY --from=builder /bin/shield /shield
COPY config/shield.yaml /etc/ebpf-shield/shield.yaml
ENTRYPOINT ["/shield", "--config", "/etc/ebpf-shield/shield.yaml"]
