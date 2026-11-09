FROM golang:1.23-alpine AS builder

WORKDIR /src
RUN apk add --no-cache git ca-certificates

COPY go.mod ./
COPY main.go ./

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /my-vpn-2 main.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /my-vpn-2 /usr/local/bin/my-vpn-2

EXPOSE 8080 8888
ENTRYPOINT ["/usr/local/bin/my-vpn-2"]
