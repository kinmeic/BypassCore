.PHONY: build test run run-test run-resolve observe tidy clean

BINARY := bypasscore
CONFIG ?= examples/config.example.json
VERSION ?= 1.4.5
LDFLAGS ?= -X main.version=$(VERSION)

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/bypasscore

# daemon 模式: 启动 tproxy 监听 + 路由 + 出站
run: build
	./bin/$(BINARY) -config $(CONFIG) -run

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
