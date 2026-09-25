# Makefile — Сборка прототипа защищённого туннеля
# Зависимости: libsodium-dev, Linux kernel headers

CC       ?= gcc
CFLAGS   = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS  = -lsodium
PREFIX   ?= /usr/local

SRCS_COMMON = common.c proto.c crypto.c tun.c
OBJS_COMMON = $(SRCS_COMMON:.c=.o)

.PHONY: all clean install test

all: tunnel_server tunnel_client test_proto

tunnel_server: server.c $(OBJS_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tunnel_client: client.c $(OBJS_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_proto: test_proto.c $(OBJS_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c tunnel.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: test_proto
	./test_proto

install: all
	install -m 755 tunnel_server tunnel_client $(PREFIX)/bin/

clean:
	rm -f *.o tunnel_server tunnel_client test_proto
