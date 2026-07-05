.PHONY: build gateway admin run test test-integration tidy docker

build: gateway admin

gateway:
	go build -o bin/gateway ./cmd/gateway

admin:
	go build -o bin/beacon-admin ./cmd/admin

run: gateway
	./bin/gateway

test:
	go test ./...

# Integration tests need a local DynamoDB (e.g. amazon/dynamodb-local on :8000).
test-integration:
	go test -tags integration ./... -run Integration

tidy:
	go mod tidy

docker:
	docker compose build
