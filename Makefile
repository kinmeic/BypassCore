.PHONY: build test run run-test run-resolve observe tidy clean

BINARY := bypasscore
CONFIG ?= examples/config.example.json

build:
	go build -o bin/$(BINARY) ./cmd/bypasscore

run: build
	./bin/$(BINARY) -config $(CONFIG)

# 路由决策演示: make run-test DEST=tcp:www.google.com:443
run-test: build
	./bin/$(BINARY) -config $(CONFIG) -test "$(DEST)"

# DNS 解析演示: make run-resolve DOMAIN=example.com
run-resolve: build
	./bin/$(BINARY) -config $(CONFIG) -resolve "$(DOMAIN)"

# Observatory 探测演示
observe: build
	./bin/$(BINARY) -config $(CONFIG) -observe

test:
	go test ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/
