SHELL := /bin/zsh

.PHONY: run dev test build tidy

run:
	go run cmd/api/main.go

dev:
	air

build:
	go build -o bin/api cmd/api/main.go

test:
	go test ./... -v

tidy:
	go mod tidy
