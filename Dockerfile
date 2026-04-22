FROM golang:1.25-alpine AS build

RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=1 go build \
    -ldflags "-s -w -X main.version=${VERSION} -extldflags '-static'" \
    -o /dhcp-helper .

FROM scratch
COPY --from=build /dhcp-helper /dhcp-helper
ENTRYPOINT ["/dhcp-helper"]
