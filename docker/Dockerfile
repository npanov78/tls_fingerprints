FROM golang:1.23.2 AS builder

WORKDIR /build

COPY . .

RUN go mod download
RUN go mod tidy

RUN apt-get update && apt-get install -y libpcap-dev

RUN CGO_ENABLED=1 go build -o /tls-fingerprints cmd/app/main.go

FROM alpine:latest
RUN apk add --no-cache libpcap

RUN addgroup -S local_group && adduser -S local_user -G local_group

COPY --from=builder tls-fingerprints /tls-fingerprints

USER local_user

ENTRYPOINT ["/tls-fingerprints"]