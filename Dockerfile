# KERB-SLEUTH Dockerfile
# Multi-stage build for optimal image size

FROM golang:1.21-alpine AS builder

# Install git and ca-certificates for HTTPS
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o kerb-sleuth ./cmd/kerb-sleuth

# Final stage - minimal image
FROM alpine:latest

# Install ca-certificates for HTTPS requests and file utilities
RUN apk --no-cache add ca-certificates file

# Create non-root user
RUN addgroup -g 1000 sleuth && \
    adduser -D -s /bin/sh -u 1000 -G sleuth sleuth

WORKDIR /home/sleuth/

# Copy the binary from builder stage
COPY --from=builder /app/kerb-sleuth .
COPY --from=builder /app/configs ./configs/
COPY --from=builder /app/tests/sample_data ./tests/sample_data/

# Change ownership
RUN chown -R sleuth:sleuth /home/sleuth/

# Switch to non-root user
USER sleuth

# Make binary executable
RUN chmod +x kerb-sleuth

# Expose volume for data
VOLUME ["/data"]

# Default command - show help
ENTRYPOINT ["./kerb-sleuth"]
CMD ["--help"]
