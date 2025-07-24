# OrAura Backend Makefile

# Variables
APP_NAME := oraura-backend
BUILD_DIR := ./build
CMD_DIR := ./cmd/server
DOCKER_IMAGE := oraura/backend
DOCKER_TAG := latest

# Go related variables
GO := go
GOFMT := gofmt
GOLINT := golangci-lint

# Default target
.PHONY: help
help: ## Show help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Development
.PHONY: dev
dev: ## Start development server with hot reload
	@echo "Starting development server..."
	air -c .air.toml

.PHONY: run
run: ## Run the application
	@echo "Running application..."
	$(GO) run $(CMD_DIR)/main.go

.PHONY: build
build: ## Build the application
	@echo "Building application..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(APP_NAME) $(CMD_DIR)/main.go

.PHONY: build-linux
build-linux: ## Build for Linux
	@echo "Building Linux application..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(APP_NAME)-linux $(CMD_DIR)/main.go

# Testing
.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	$(GO) test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	$(GO) test -v -short ./...

.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GO) test -bench=. ./...

# Code quality
.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting code..."
	$(GOFMT) -w .

.PHONY: lint
lint: ## Run golangci-lint
	@echo "Running linter..."
	$(GOLINT) run

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet ./...

.PHONY: check
check: fmt vet lint test ## Run all checks

# Dependencies
.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GO) mod download

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	$(GO) mod tidy

.PHONY: deps-vendor
deps-vendor: ## Vendor dependencies
	@echo "Vendoring dependencies..."
	$(GO) mod vendor

# Database
.PHONY: db-up
db-up: ## Start database with docker-compose
	@echo "Starting database..."
	docker compose up -d postgres redis

.PHONY: db-down
db-down: ## Stop database
	@echo "Stopping database..."
	docker compose down

.PHONY: db-reset
db-reset: ## Reset database (WARNING: This will delete all data)
	@echo "Resetting database..."
	docker compose down -v
	docker compose up -d postgres redis

# Docker
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "Running Docker container..."
	docker run -p 8080:8080 $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-up
docker-up: ## Start all services with docker-compose
	@echo "Starting all services..."
	docker compose up -d

.PHONY: docker-down
docker-down: ## Stop all services
	@echo "Stopping all services..."
	docker compose down

.PHONY: docker-logs
docker-logs: ## Show docker-compose logs
	docker compose logs -f

# Clean
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build files..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

.PHONY: clean-all
clean-all: clean ## Clean everything including Docker
	@echo "Cleaning Docker images..."
	docker compose down -v --rmi all
	docker system prune -f

# Generate
.PHONY: gen
gen: ## Generate code (swagger, mocks, etc.)
	@echo "Generating code..."
	$(GO) generate ./...

.PHONY: swagger
swagger: ## Generate Swagger docs
	@echo "Generating Swagger documentation..."
	swag init -g cmd/server/main.go

# Setup
.PHONY: setup
setup: deps ## Setup development environment
	@echo "Setting up development environment..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env file from .env.example"; fi
	@echo "Please edit .env file with your configuration"
	@echo "Run 'make db-up' to start the database"
	@echo "Run 'make run' to start the application"

# Production
.PHONY: prod-build
prod-build: test build-linux ## Build for production
	@echo "Production build completed"

.PHONY: deploy
deploy: prod-build ## Deploy (customize as needed)
	@echo "Deploying application..."
	# Add your deployment commands here

# Migration helpers (if using migrate tool)
.PHONY: migrate-up
migrate-up: ## Run database migrations up
	@echo "Running migrations up..."
	migrate -path migrations -database "$$DATABASE_URL" up

.PHONY: migrate-down
migrate-down: ## Run database migrations down
	@echo "Running migrations down..."
	migrate -path migrations -database "$$DATABASE_URL" down

.PHONY: migrate-create
migrate-create: ## Create new migration file
	@echo "Creating migration: $(name)"
	migrate create -ext sql -dir migrations -seq $(name)

# Utilities
.PHONY: ps
ps: ## Show running processes
	docker compose ps

.PHONY: logs
logs: ## Show application logs
	docker compose logs -f app