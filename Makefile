.PHONY: proto build test lint docker-up docker-down clean

proto:
	bash scripts/gen-proto.sh

build: proto
	mkdir -p bin
	go build -o bin/fortress-gw ./cmd/fortress-gw
	go build -o bin/fortress-ctl ./cmd/fortress-ctl
	cd rust && cargo build --release

test:
	go test -race ./...
	cd rust && cargo test

lint:
	go vet ./...
	cd rust && cargo clippy -- -D warnings

docker-up:
	docker compose -f docker/docker-compose.yml up -d

docker-down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf bin/
	cd rust && cargo clean
