export TEST_TIMEOUT_IN_SECONDS := 240
export PKG := github.com/ynori7/credential-detector
export ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

install:
	go install -v $(PKG)/...
.PHONY: install

install-dependencies:
	go get -t -v $(PKG)/...
	go test -i -v $(PKG)/...
.PHONY: install-dependencies

install-tools:
	# linting
	go get -u -v golang.org/x/lint/golint/...

	# code coverage
	go get -u -v golang.org/x/tools/cmd/cover
	go get -u -v github.com/onsi/ginkgo/ginkgo/...
	go get -u -v github.com/modocache/gover/...
	go get -u -v github.com/mattn/goveralls/...
.PHONY: install-tools

lint:
	$(ROOT_DIR)/scripts/lint.sh
.PHONY: lint

test:
	go test -race -test.timeout "$(TEST_TIMEOUT_IN_SECONDS)s" ./... 
.PHONY: test

test-verbose:
	go test -race -test.timeout "$(TEST_TIMEOUT_IN_SECONDS)s" -v ./... 
.PHONY: test-verbose

test-verbose-with-coverage:
	go test -race -coverprofile credential-detector.coverprofile -test.timeout "$(TEST_TIMEOUT_IN_SECONDS)s" -v ./...
.PHONY: test-verbose-with-coverage
