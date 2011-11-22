
CC = gcc
CFLAGS = -Wall -ggdb -O0
INCLUDE = -I./.
LIB = -ldl -lpthread -lpcap
SRCC = threadtest.cpp
TARGET = threadtest

all: $(TARGET)

$(TARGET): $(SRCC) navl.h libnavl.so
	$(CC) $(SRCC) $(CFLAGS) $(INCLUDE) $(LIB) -rdynamic libnavl.so -o $(TARGET)

clean:
	@rm -f $(TARGET)
