FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build --tags netgo,osusergo -o /go-i2p

FROM alpine:3.21

RUN adduser -D -h /home/i2p i2p
RUN mkdir -p /home/i2p/.go-i2p/
RUN chown -R i2p:i2p /home/i2p
RUN chmod -R 700 /home/i2p

COPY --from=builder /go-i2p /usr/local/bin/go-i2p

USER i2p
WORKDIR /home/i2p

# I2CP and I2PControl
#EXPOSE 7654 7650
# Set DEBUG_I2P=debug to enable debug logging
ENV DEBUG_I2P=debug
ENTRYPOINT ["go-i2p"]
