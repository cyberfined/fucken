CC=gcc
CFLAGS=-std=c11 -Wall -O3
.PHONY: all clean
all: fucken
fucken: fucken.o
	$(CC) fucken.o -o fucken
fucken.o: fucken.c
	$(CC) $(CFLAGS) -c fucken.c -o fucken.o
clean:
	rm -f fucken fucken.o
