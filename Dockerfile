FROM golang:1.22.0-alpine as builder

WORKDIR /build
COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go mod download
RUN go build -o ./sso_service ./cmd/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /build/sso_service /app/
COPY --from=builder /build/.env /app/

CMD ["./sso_service"]