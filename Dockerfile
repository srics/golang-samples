FROM golang:latest as builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64
WORKDIR /build
COPY . .
RUN go build -o kmsdemo cmd/kms/kmsdemo.go

FROM alpine:3.8 as alpine
RUN apk --no-cache add ca-certificates

FROM alpine
COPY --from=builder /build/kmsdemo /
COPY --from=builder /build/master.enc /
# for truststore
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt


