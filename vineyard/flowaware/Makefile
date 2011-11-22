CXXFLAGS = -Wall -ggdb -O0
INCLUDE = -I./.
LIB = -ldl -lpthread -lpcap
SRCCXX = flowaware.cpp
TARGET = flowaware

all: $(TARGET)

$(TARGET): $(SRCCXX) navl.h libnavl.so
	$(CC) $(SRCCXX) $(CXXFLAGS) $(INCLUDE) $(LIB) libnavl.so -o $(TARGET)

clean:
	@rm -f $(TARGET)
