build:
	go build -v
.PHONY: build

unit-test:
	go test -v -cover -short
.PHONY: unit-test

test:
	go test -v -cover
.PHONY: test

clean:
	go clean
.PHONY: clean

all: clean build test
.PHONY: all
