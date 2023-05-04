
all: run

run:
	go run ./cmd/... -config=dev.yml

build:
	go build -o dnstwist ./cmd/...

clean:
	rm dnstwist || true
