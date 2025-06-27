# Dockerfile for squareup/certstrap
#
# To build this image:
#     docker build -t squareup/certstrap .
#
# To run certstrap from the image (for example):
#     docker run --rm squareup/certstrap --version

FROM golang:1.19-alpine as build

WORKDIR /app

COPY go.mod .
COPY go.sum .

# Download dependencies
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 go build -buildvcs=false -o /usr/bin/certstrap github.com/square/certstrap

# Create a multi-stage build with the binary
FROM gcr.io/distroless/static

COPY --from=build /usr/bin/certstrap /usr/bin/certstrap

ENTRYPOINT ["/usr/bin/certstrap"]
