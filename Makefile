CFLAGS+=-std=c99 -Wall -Wpedantic
# use -pie so that our text segment doesn't collide with the plan 9
# application. -static-pie also works.
CFLAGS+=-fpie
LDFLAGS+=-pie

-include config.mk

OBJ=\
	nine.o\
	start.o\

HDR=\
	arg.h\
	sys.h\
	tos.h\
	util.h\

.PHONY: all
all: nine

$(OBJ): $(HDR)

nine: nine.o start.o
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

.PHONY: clean
clean:
	rm -f nine $(OBJ)
