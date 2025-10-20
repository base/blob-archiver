# Оптимизированный Makefile для Blob Validator
SHELL := /bin/bash

# Переменные сборки
BINARY_NAME := blob-validator
BIN_DIR := ./bin
CMD_DIR := ./cmd
OUTPUT := $(BIN_DIR)/$(BINARY_NAME)

# Платформа и архитектура (с автоопределением)
TARGETOS ?= $(shell go env GOOS)
TARGETARCH ?= $(shell go env GOARCH)

# Git информация для версионирования
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Go настройки
GO := go
GO111MODULE := on
GOFLAGS := -v
CGO_ENABLED ?= 0

# Оптимизированные LDFLAGS
LDFLAGS := -s -w \
	-X main.version=$(GIT_TAG) \
	-X main.commit=$(GIT_COMMIT) \
	-X main.date=$(BUILD_DATE)

# Дополнительные флаги оптимизации для production
LDFLAGS_PROD := $(LDFLAGS) \
	-extldflags "-static"

# Флаги компиляции для оптимизации
GCFLAGS := -trimpath
ASMFLAGS := -trimpath

# Тестовые флаги
TEST_FLAGS := -v -race -timeout 5m
TEST_FLAGS_COVERAGE := $(TEST_FLAGS) -coverprofile=coverage.out -covermode=atomic
TEST_FLAGS_BENCH := -bench=. -benchmem -benchtime=10s

##
# Основные таргеты
##
.PHONY: all
all: clean deps lint test build

.PHONY: blob-validator
blob-validator: build

##
# Сборка
##
.PHONY: build
build: create-bin-dir
	@echo "Building $(BINARY_NAME) for $(TARGETOS)/$(TARGETARCH)..."
	@env GO111MODULE=$(GO111MODULE) \
		GOOS=$(TARGETOS) \
		GOARCH=$(TARGETARCH) \
		CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) build $(GOFLAGS) \
		-ldflags "$(LDFLAGS)" \
		-gcflags "$(GCFLAGS)" \
		-asmflags "$(ASMFLAGS)" \
		-o $(OUTPUT) \
		$(CMD_DIR)/main.go
	@echo "✓ Built: $(OUTPUT)"
	@ls -lh $(OUTPUT)

# Production сборка с максимальными оптимизациями
.PHONY: build-prod
build-prod: create-bin-dir
	@echo "Building $(BINARY_NAME) for production..."
	@env GO111MODULE=$(GO111MODULE) \
		GOOS=$(TARGETOS) \
		GOARCH=$(TARGETARCH) \
		CGO_ENABLED=0 \
		$(GO) build \
		-ldflags "$(LDFLAGS_PROD)" \
		-gcflags "$(GCFLAGS) -c=4" \
		-asmflags "$(ASMFLAGS)" \
		-trimpath \
		-o $(OUTPUT) \
		$(CMD_DIR)/main.go
	@echo "✓ Production build complete: $(OUTPUT)"
	@ls -lh $(OUTPUT)

# Быстрая сборка для development (без оптимизаций)
.PHONY: build-dev
build-dev: create-bin-dir
	@echo "Building $(BINARY_NAME) for development (fast)..."
	@env GO111MODULE=$(GO111MODULE) \
		GOOS=$(TARGETOS) \
		GOARCH=$(TARGETARCH) \
		$(GO) build -v -o $(OUTPUT) $(CMD_DIR)/main.go
	@echo "✓ Development build complete"

# Кросс-компиляция для популярных платформ
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	@$(MAKE) build-linux-amd64
	@$(MAKE) build-linux-arm64
	@$(MAKE) build-darwin-amd64
	@$(MAKE) build-darwin-arm64
	@$(MAKE) build-windows-amd64
	@echo "✓ All platform builds complete"

.PHONY: build-linux-amd64
build-linux-amd64:
	@TARGETOS=linux TARGETARCH=amd64 $(MAKE) build OUTPUT=$(BIN_DIR)/$(BINARY_NAME)-linux-amd64

.PHONY: build-linux-arm64
build-linux-arm64:
	@TARGETOS=linux TARGETARCH=arm64 $(MAKE) build OUTPUT=$(BIN_DIR)/$(BINARY_NAME)-linux-arm64

.PHONY: build-darwin-amd64
build-darwin-amd64:
	@TARGETOS=darwin TARGETARCH=amd64 $(MAKE) build OUTPUT=$(BIN_DIR)/$(BINARY_NAME)-darwin-amd64

.PHONY: build-darwin-arm64
build-darwin-arm64:
	@TARGETOS=darwin TARGETARCH=arm64 $(MAKE) build OUTPUT=$(BIN_DIR)/$(BINARY_NAME)-darwin-arm64

.PHONY: build-windows-amd64
build-windows-amd64:
	@TARGETOS=windows TARGETARCH=amd64 $(MAKE) build OUTPUT=$(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe

##
# Тестирование
##
.PHONY: test
test:
	@echo "Running tests with race detector..."
	@$(GO) test $(TEST_FLAGS) ./...

# Быстрые тесты без race detector
.PHONY: test-fast
test-fast:
	@echo "Running fast tests..."
	@$(GO) test -v -short ./...

# Тесты с покрытием кода
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@$(GO) test $(TEST_FLAGS_COVERAGE) ./...
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

# Показать текущее покрытие
.PHONY: coverage-report
coverage-report: test-coverage
	@$(GO) tool cover -func=coverage.out | tail -1

# Бенчмарки
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	@$(GO) test $(TEST_FLAGS_BENCH) ./...

# Бенчмарки с профилированием CPU
.PHONY: bench-cpu
bench-cpu:
	@echo "Running benchmarks with CPU profiling..."
	@$(GO) test -bench=. -benchmem -cpuprofile=cpu.prof ./...
	@echo "✓ CPU profile: cpu.prof"
	@echo "View with: go tool pprof cpu.prof"

# Бенчмарки с профилированием памяти
.PHONY: bench-mem
bench-mem:
	@echo "Running benchmarks with memory profiling..."
	@$(GO) test -bench=. -benchmem -memprofile=mem.prof ./...
	@echo "✓ Memory profile: mem.prof"
	@echo "View with: go tool pprof mem.prof"

##
# Зависимости
##
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	@$(GO) mod download
	@$(GO) mod verify
	@echo "✓ Dependencies verified"

.PHONY: deps-tidy
deps-tidy:
	@echo "Tidying dependencies..."
	@$(GO) mod tidy
	@echo "✓ Dependencies tidied"

.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	@$(GO) get -u ./...
	@$(GO) mod tidy
	@echo "✓ Dependencies updated"

##
# Качество кода
##
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout 5m ./...; \
	else \
		echo "⚠ golangci-lint not found, skipping..."; \
		echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@$(GO) fmt ./...
	@echo "✓ Code formatted"

.PHONY: vet
vet:
	@echo "Running go vet..."
	@$(GO) vet ./...
	@echo "✓ Vet check passed"

.PHONY: check
check: fmt vet lint
	@echo "✓ All checks passed"

##
# Очистка
##
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html
	@rm -f cpu.prof mem.prof
	@rm -f *.test
	@echo "✓ Cleaned"

.PHONY: clean-cache
clean-cache:
	@echo "Cleaning Go cache..."
	@$(GO) clean -cache -testcache -modcache
	@echo "✓ Cache cleaned"

##
# Утилиты
##
.PHONY: create-bin-dir
create-bin-dir:
	@mkdir -p $(BIN_DIR)

.PHONY: install
install: build
	@echo "Installing to GOPATH..."
	@cp $(OUTPUT) $(shell go env GOPATH)/bin/
	@echo "✓ Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	@$(OUTPUT)

.PHONY: version
version:
	@echo "Version: $(GIT_TAG)"
	@echo "Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Target: $(TARGETOS)/$(TARGETARCH)"

.PHONY: size
size: build
	@echo "Binary size analysis:"
	@ls -lh $(OUTPUT)
	@if command -v du >/dev/null 2>&1; then \
		du -h $(OUTPUT); \
	fi

# Docker сборка (опционально)
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):$(GIT_TAG) -t $(BINARY_NAME):latest .
	@echo "✓ Docker image built"

##
# CI/CD таргеты
##
.PHONY: ci
ci: deps check test build
	@echo "✓ CI pipeline complete"

.PHONY: ci-full
ci-full: deps check test-coverage bench build-all
	@echo "✓ Full CI pipeline complete"

##
# Помощь
##
.PHONY: help
help:
	@echo "Blob Validator Build System"
	@echo ""
	@echo "Build targets:"
	@echo "  build              - Build binary (default: $(TARGETOS)/$(TARGETARCH))"
	@echo "  build-dev          - Fast build for development"
	@echo "  build-prod         - Optimized production build"
	@echo "  build-all          - Build for all platforms"
	@echo "  blob-validator     - Alias for build"
	@echo ""
	@echo "Test targets:"
	@echo "  test               - Run tests with race detector"
	@echo "  test-fast          - Quick tests without race detector"
	@echo "  test-coverage      - Tests with coverage report"
	@echo "  bench              - Run benchmarks"
	@echo "  bench-cpu          - Benchmarks with CPU profiling"
	@echo "  bench-mem          - Benchmarks with memory profiling"
	@echo ""
	@echo "Code quality:"
	@echo "  lint               - Run golangci-lint"
	@echo "  fmt                - Format code"
	@echo "  vet                - Run go vet"
	@echo "  check              - Run all quality checks"
	@echo ""
	@echo "Dependencies:"
	@echo "  deps               - Download and verify dependencies"
	@echo "  deps-tidy          - Tidy dependencies"
	@echo "  deps-update        - Update all dependencies"
	@echo ""
	@echo "Utilities:"
	@echo "  clean              - Remove build artifacts"
	@echo "  clean-cache        - Clean Go cache"
	@echo "  install            - Install to GOPATH"
	@echo "  run                - Build and run"
	@echo "  version            - Show version info"
	@echo "  size               - Show binary size"
	@echo ""
	@echo "CI/CD:"
	@echo "  ci                 - Run CI pipeline"
	@echo "  ci-full            - Full CI with coverage and benchmarks"
	@echo ""
	@echo "Environment variables:"
	@echo "  TARGETOS           - Target OS (current: $(TARGETOS))"
	@echo "  TARGETARCH         - Target architecture (current: $(TARGETARCH))"
	@echo "  CGO_ENABLED        - Enable CGO (current: $(CGO_ENABLED))"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test-coverage"
	@echo "  make TARGETOS=linux TARGETARCH=amd64 build"
	@echo "  make build-all"

.DEFAULT_GOAL := help
