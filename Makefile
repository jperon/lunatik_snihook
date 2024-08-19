# SPDX-FileCopyrightText: (c) 2024 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
# SPDX-License-Identifier: MIT OR GPL-2.0-only

NAME = snihook
CFLAGS = -O2 -Wall -I/usr/local/include/lunatik
LUA_MODULE_DIR = /lib/modules/lua

all:
	moonc . || echo "Install MoonScript if you intend to modify sources."

install:
	mkdir ${LUA_MODULE_DIR}/${NAME} || true
	cp [!c]*.lua ${LUA_MODULE_DIR}/${NAME}
	cp -n config.lua ${LUA_MODULE_DIR}/${NAME}

uninstall:
	rm -rf ${LUA_MODULE_DIR}/${NAME}
