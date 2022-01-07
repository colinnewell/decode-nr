VERSION  := $(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD)

all: decode-nr

decode-nr: cmd/decode-nr/main.go connections/*.go go.*
	go build -o decode-nr -ldflags "-X github.com/colinnewell/pcap-cli/cli.Version=$(VERSION)" cmd/decode-nr/*.go

test: .force
	go test ./...

# e2e-test: decode-nr
# 	test/e2e-tests.sh

# fake target (don't create a file or directory with this name)
# allows us to ensure a target always gets run, even if there is a folder or
# file with that name.
# This is different to doing make -B to ensure you do a rebuild.
# This is here because we have a test directory which makes the make test think
# it's 'built' already.
.force:

clean:
	rm decode-nr

install:
	cp decode-nr /usr/local/bin

lint:
	golangci-lint run
	./ensure-gofmt.sh
