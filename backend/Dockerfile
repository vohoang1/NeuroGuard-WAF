# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY . .
# Download and verify dependencies based on the source code imports
RUN go mod tidy

# Build statically linked binary (no CGO) for speed and small image size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/neuroguard-api cmd/server/main.go

# Stage 2: Minimal Distroless Image
# Distroless contains NO shell, packaging tools, or useless binaries reducing surface area.
FROM gcr.io/distroless/static-debian11

# Secure the application
USER nonroot:nonroot

COPY --from=builder --chown=nonroot:nonroot /app/neuroguard-api /neuroguard-api

EXPOSE 8081

CMD ["/neuroguard-api"]
