# DNS Proxy Filter Server
# Copyright (c) 2010 Untangle, Inc.
# All Rights Reserved
# Written by Michael A. Hotz

VERSION = 1.0.0
DEBUG = -g3 -ggdb
#GPROF = -pg
#SPEED = -O2

BUILDID := "$(shell date -u "+%G/%m/%d %H:%M:%S UTC")"
SYSTEM := $(shell uname)
ARCH := $(shell uname -m)

ifeq ($(SYSTEM),Linux)
  PLATFORM = -D__LINUX__
  LIBFILES = -lpthread -lrt -ldl -lnetfilter_queue
else
  $(error ERROR: Unsupported platform '$(SYSTEM)')
endif

CXXFLAGS = $(DEBUG) $(GPROF) $(SPEED) -Wall -pthread

CXXFLAGS += -DVERSION=\"$(VERSION)\"
CXXFLAGS += -DBUILDID=\"$(BUILDID)\"
CXXFLAGS += -DPLATFORM=\"$(PLATFORM)\"

OBJFILES := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
OBJFILES += vineyard/lib/libnavl.so

classd : $(OBJFILES)
	$(CXX) $(DEBUG) $(GPROF) $(SPEED) $(OBJFILES) $(LIBFILES) -o classd

$(OBJFILES) : Makefile *.h

clean : force
	rm -r -f Release
	rm -r -f Debug
	rm -f classd
	rm -f gmon.out
	rm -f *.vtg
	rm -f *.o

force :

