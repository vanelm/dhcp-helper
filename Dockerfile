FROM golang:1.25-bookworm AS build

RUN rm -f /etc/apt/apt.conf.d/docker-clean \
    && printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\nAPT::Get::AllowUnauthenticated "true";\nAcquire::CompressionTypes::Order:: "gz";\n' \
       > /etc/apt/apt.conf.d/99no-check \
    && apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags "-s -w -X main.version=${VERSION}" -o /dhcp-helper .

FROM debian:bookworm-slim
RUN printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\nAPT::Get::AllowUnauthenticated "true";\nAcquire::CompressionTypes::Order:: "gz";\n' \
    > /etc/apt/apt.conf.d/99no-check \
    && apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /dhcp-helper /usr/local/bin/
ENTRYPOINT ["dhcp-helper"]
