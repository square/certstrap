# Dockerfile for squareup/certstrap
#
# To build this image:
#     docker build -t squareup/certstrap .
#
# To run certstrap from the image (for example):
#     docker run --rm squareup/certstrap --version

FROM golang:1.13-alpine as build

MAINTAINER Cedric Staub "cs@squareup.com"

WORKDIR /app

COPY go.mod .
COPY go.sum .

# Download dependencies
RUN go mod download

# Copy source
COPY . .

# Build
RUN go build -o /usr/bin/certstrap github.com/square/certstrap

# Create a multi-stage build with the binary
FROM alpine

COPY --from=build /usr/bin/certstrap /usr/bin/certstrap

ENTRYPOINT ["/usr/bin/certstrap"]
