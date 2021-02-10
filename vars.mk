#    ___          _        _    __   __           
#   | _ \_ _ ___ (_)___ __| |_  \ \ / /_ _ _ _ ___
#   |  _/ '_/ _ \| / -_) _|  _|  \ V / _` | '_(_-<
#   |_| |_| \___// \___\__|\__|   \_/\__,_|_| /__/
#              |__/                               
PROJECT=foo
TARGET=$(shell ${CC} -dumpmachine)

SRC_OBJS=$(patsubst src/%.c,obj/$(TARGET)/%.c.o,$(wildcard src/*.c))
INC+=-I./inc
LIB+=
CFLAGS+=-Wall -g
LINK+=-lm
