# SPDX-FileCopyrightText: (c) 2024 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
# SPDX-License-Identifier: MIT OR GPL-2.0-only

NAME = sniblock
CFLAGS = -O2 -Wall -I../lib
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)
LUA_MODULE_DIR = /lib/modules/lua

all:
	make libxt_${NAME}.so;
	moonc .

install:
	cp *.so ${XTABLES_SO_DIR}
	mkdir ${LUA_MODULE_DIR}/${NAME} || true
	cp *.lua ${LUA_MODULE_DIR}/${NAME}

uninstall:
	rm -f ${XTABLES_SO_DIR}/libxt_${NAME}.so
	rm -rf ${LUA_MODULE_DIR}/${NAME}

clean:
	rm -f *.o *.so

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

