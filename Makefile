CFLAGS+=-std=c99 -Wall -Wpedantic

-include config.mk

nine: start.s

.PHONY: all
all: nine

.PHONY: clean
clean:
	rm -f nine
