.PHONY: install build lint test tidy clean

MAKEFILE_DIR          = $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR             = $(MAKEFILE_DIR)/build
GOLANGCI_LINT_VERSION = v2.4.0

all: tidy lint test build

install:
	cd $(MAKEFILE_DIR) && go install .

build:
	cd $(MAKEFILE_DIR) && go build -o $(BUILD_DIR)/openpgp .

lint:
	cd $(MAKEFILE_DIR) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --config .github/golangci.yml

test:
	cd $(MAKEFILE_DIR) && go test -v ./...

tidy:
	cd $(MAKEFILE_DIR) && go mod tidy

clean:
	rm -rf $(BUILD_DIR)
