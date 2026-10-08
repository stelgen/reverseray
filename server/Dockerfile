# syntax=docker/dockerfile:1
# ReverseRay server — distroless, non-root, static.
# v0.8.3: НИКАКОГО busybox/шелла в образе. Прежний governor (busybox sh из
# alpine) не работал в distroless: busybox в alpine — динамический PIE
# (интерпретатор /lib/ld-musl-x86_64.so.1 отсутствует в distroless) →
# «exec /bin/busybox: no such file or directory». Supervisor теперь —
# подкоманда самого статического бинаря: `reverseray governor` (governor.go).
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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/reverseray /reverseray
# Каталог состояния с владельцем 65532: при named volume Docker копирует
# права из образа при первом монтировании (bind-mount использует владельца хоста).
COPY --from=build --chown=65532:65532 /state /var/lib/reverseray
USER 65532:65532
EXPOSE 443 1080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/reverseray", "healthcheck"]
# v0.8.3: governor — код в самом бинаре (рестарты ≥ RR_RESTART_DELAY с,
# RR_RESTART_MAX падений подряд → контейнер умирает с ошибкой).
ENTRYPOINT ["/reverseray", "governor"]
CMD ["run"]