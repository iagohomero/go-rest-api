FROM golang:1.24.0 AS build

WORKDIR /app
COPY . .
# Copy migrations directory for embedding
COPY migrations/ ./migrations/
RUN go clean --modcache
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

FROM alpine:latest

RUN apk add --no-cache curl

WORKDIR /root
COPY --from=build /app/main .
# Copy migrations directory for runtime access
COPY --from=build /app/migrations ./migrations
# Copy .env file if it exists (optional for development)
COPY --from=build /app/.env* ./

EXPOSE 8080
CMD ["./main"]

