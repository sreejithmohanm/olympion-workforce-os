.PHONY: lint test build ci

lint:
	./scripts/lint.sh

test:
	./scripts/test.sh

build:
	./scripts/build.sh

ci: lint test build
