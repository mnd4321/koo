CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

TARGETS := init_module_loader hello_comm_test

.PHONY: all clean

all: $(TARGETS)

init_module_loader: init_module_loader.c
	$(CC) $(CFLAGS) -o $@ $<

hello_comm_test: hello_comm_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
