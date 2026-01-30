# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
# Using golang:1.24-alpine as specified in go.mod
FROM golang:1.24-alpine AS builder

# Install git (required if you add external dependencies later)
RUN apk add --no-cache git

WORKDIR /app

# Copy module files first to leverage Docker cache
COPY go.mod ./

# Download dependencies (No go.sum provided, but good practice to include tidy/download)
RUN go mod tidy && go mod download

# Copy the source code
COPY . .

# Build the binary
# CGO_ENABLED=0 ensures a statically linked binary for portability
# -ldflags="-s -w" strips debug information to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o trilochana .

# -----------------------------------------------------------------------------
# Stage 2: Runner
# -----------------------------------------------------------------------------
FROM alpine:latest

# Install ca-certificates in case the tool needs to make external web calls in future
RUN apk --no-cache add ca-certificates bash

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/trilochana /usr/local/bin/trilochana

# Create a directory for mounting the code to be scanned
RUN mkdir /scan

# Set the binary as the entrypoint
ENTRYPOINT ["trilochana"]

# Default command flags (Scan the /scan directory by default)
CMD ["--path", "/scan"]