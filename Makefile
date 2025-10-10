.PHONY: help dev build run test test-coverage lint docker-build docker-up docker-down migrate-up migrate-down docker-migrate-up docker-migrate-down swag clean deps

include .env
export

# Variables
APP_NAME=go-rest-api
DOCKER_COMPOSE=docker-compose
GO=go
GOTEST=$(GO) test
GOCOVER=$(GO) tool cover
MAIN_PATH=./cmd/api
DATABASE_URL=postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[0;33m
NC=\033[0m # No Color

help: ## Show this help message
	@echo "${GREEN}Available commands:${NC}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${YELLOW}%-20s${NC} %s\n", $$1, $$2}'

dev: ## Run development server with hot reload (requires air)go
	@echo "${GREEN}Starting development server...${NC}"
	@air

build: ## Build the application
	@echo "${GREEN}Building application...${NC}"
	@$(GO) build -o bin/$(APP_NAME) $(MAIN_PATH)/main.go
	@echo "${GREEN}Build complete: bin/$(APP_NAME)${NC}"

run: build ## Run the built application
	@echo "${GREEN}Starting application...${NC}"
	@./bin/$(APP_NAME)

test: ## Run tests
	@echo "${GREEN}Running tests...${NC}"
	@$(GOTEST) -race ./...

test-coverage: ## Run tests with coverage
	@echo "${GREEN}Running tests with coverage...${NC}"
	@$(GOTEST) -race -coverprofile=coverage.out ./...
	@$(GOCOVER) -html=coverage.out -o coverage.html
	@echo "${GREEN}Coverage report generated: coverage.html${NC}"

lint: ## Run linter (requires golangci-lint)
	@echo "${GREEN}Running linter...${NC}"
	@golangci-lint run --timeout=5m

docker-build: ## Build Docker image
	@echo "${GREEN}Building Docker image...${NC}"
	@docker build -t $(APP_NAME):latest .
	@echo "${GREEN}Docker image built: $(APP_NAME):latest${NC}"

docker-up: ## Start Docker containers
	@echo "${GREEN}Starting Docker containers...${NC}"
	@$(DOCKER_COMPOSE) up -d
	@echo "${GREEN}Containers started${NC}"

docker-down: ## Stop Docker containers
	@echo "${GREEN}Stopping Docker containers...${NC}"
	@$(DOCKER_COMPOSE) down
	@echo "${GREEN}Containers stopped${NC}"

docker-logs: ## Show Docker logs
	@$(DOCKER_COMPOSE) logs -f

migrate-create: ## Create a new migration (usage: make migrate-create name=create_users)
	@if [ -z "$(name)" ]; then \
		echo "${YELLOW}Error: Please provide a migration name${NC}"; \
		echo "Usage: make migrate-create name=create_users"; \
		exit 1; \
	fi
	@echo "${GREEN}Creating migration: $(name)${NC}"
	@migrate create -ext sql -dir migrations -seq $(name)

migrate-up: ## Run all pending migrations
	@echo "${GREEN}Running migrations...${NC}"
	@migrate -path migrations -database "$(DATABASE_URL)" up
	@echo "${GREEN}Migrations complete${NC}"

migrate-down: ## Rollback last migration
	@echo "${GREEN}Rolling back last migration...${NC}"
	@migrate -path migrations -database "$(DATABASE_URL)" down 1
	@echo "${GREEN}Rollback complete${NC}"

docker-migrate-up: ## Run all pending migrations using Docker
	@echo "${GREEN}Running migrations with Docker...${NC}"
	@docker run --rm -v $(PWD)/migrations:/migrations --network go-rest-api_go-network migrate/migrate -path /migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@postgres:5432/$(DB_NAME)?sslmode=disable" up
	@echo "${GREEN}Docker migrations complete${NC}"

docker-migrate-down: ## Rollback last migration using Docker
	@echo "${GREEN}Rolling back last migration with Docker...${NC}"
	@docker run --rm -v $(PWD)/migrations:/migrations --network go-rest-api_go-network migrate/migrate -path /migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@postgres:5432/$(DB_NAME)?sslmode=disable" down 1
	@echo "${GREEN}Docker rollback complete${NC}"

swag: ## Generate Swagger documentation
	@echo "${GREEN}Generating Swagger documentation...${NC}"
	@swag init -g $(MAIN_PATH)/main.go -o api/swagger
	@echo "${GREEN}Swagger docs generated${NC}"

clean: ## Clean build artifacts
	@echo "${GREEN}Cleaning build artifacts...${NC}"
	@rm -rf bin/ coverage.out coverage.html
	@echo "${GREEN}Clean complete${NC}"

deps: ## Download and tidy dependencies
	@echo "${GREEN}Downloading dependencies...${NC}"
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "${GREEN}Dependencies updated${NC}"

install-tools: ## Install development tools
	@echo "${GREEN}Installing development tools...${NC}"
	@go install github.com/air-verse/air@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.5.0
	@go install github.com/swaggo/swag/cmd/swag@latest
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@echo "${GREEN}Tools installed${NC}"

.DEFAULT_GOAL := help
