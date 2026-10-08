# syntax=docker/dockerfile:1
# ReverseRay server — distroless, non-root, static.
# v0.8: restart-governor (busybox sh) — упавший процесс перезапускается
# каждые RR_RESTART_DELAY секунд; бесконечный crash-loop → governor выходит
# с ошибкой (Docker видит отказ, а не молотит нагрузкой).
FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /state && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/reverseray .

# busybox (статический, musl) — шелл для governor в distroless.
FROM alpine:3.20 AS shell

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/reverseray /reverseray
COPY --from=shell /bin/busybox /bin/busybox
COPY docker-entrypoint.sh /entrypoint.sh
# Каталог состояния с владельцем 65532: при named volume Docker копирует
# права из образа при первом монтировании (bind-mount использует владельца хоста).
COPY --from=build --chown=65532:65532 /state /var/lib/reverseray
USER 65532:65532
EXPOSE 443 1080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/reverseray", "healthcheck"]
ENTRYPOINT ["/bin/busybox", "sh", "/entrypoint.sh"]
CMD ["run"]