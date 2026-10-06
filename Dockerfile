FROM golang:1.24.0-alpine3.21 as builder

RUN apk add --no-cache make gcc musl-dev linux-headers jq bash git

WORKDIR /app

COPY ./go.mod ./go.sum /app/

RUN go mod download

COPY . /app

RUN make build

FROM alpine:3.21

COPY --from=builder /app/archiver/bin/blob-archiver /usr/local/bin/blob-archiver
COPY --from=builder /app/api/bin/blob-api /usr/local/bin/blob-api
COPY --from=builder /app/validator/bin/blob-validator /usr/local/bin/blob-validator
