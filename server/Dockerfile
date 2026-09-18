# syntax=docker/dockerfile:1
# ReverseRay server — distroless, non-root, static.
FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/reverseray .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/reverseray /reverseray
USER 65532:65532
EXPOSE 443 1080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/reverseray", "healthcheck"]
ENTRYPOINT ["/reverseray"]
CMD ["run"]
