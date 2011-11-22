SYSTYPE:=$(shell uname)
CC = gcc
CFLAGS = -Wall -ggdb -O0
INCLUDE = -I./.
LIB = -lpthread -lnfnetlink -lnetfilter_queue
ifeq ($(SYSTYPE), Linux)
LIB += -ldl
else
LIB += -L/usr/local/lib -lexecinfo
endif
SRCC = qclassify.c
TARGET = qclassify

all: $(TARGET)

$(TARGET): $(SRCC) navl.h libnavl.so
	$(CC) $(SRCC) $(CFLAGS) $(INCLUDE) $(LIB) libnavl.so -o $(TARGET)

clean:
	@rm -f $(TARGET)
