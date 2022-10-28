CFLAGS+=-std=c99 -Wall -Wpedantic
# use -pie so that our text segment doesn't collide with the plan 9
# application. -static-pie also works.
CFLAGS+=-fpie
LDFLAGS+=-pie

-include config.mk

nine: start.s

.PHONY: all
all: nine

.PHONY: clean
clean:
	rm -f nine
