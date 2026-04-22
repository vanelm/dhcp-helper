FROM golang:1.25-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags "-s -w -X main.version=${VERSION}" -o /dhcp-helper .

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /dhcp-helper /usr/local/bin/
ENTRYPOINT ["dhcp-helper"]
