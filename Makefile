# Untangle Traffic Classification Daemon
# Copyright (c) 2011 Untangle, Inc.
# All Rights Reserved
# Written by Michael A. Hotz

VERSION = 1.0.0
#DEBUG = -g3 -ggdb
#GPROF = -pg
SPEED = -O2

BUILDID := "$(shell date -u "+%G/%m/%d %H:%M:%S UTC")"
SYSTEM := $(shell uname)
ARCH := $(shell uname -m)

ifeq ($(SYSTEM),Linux)
  PLATFORM = -D__LINUX__
  LIBFILES = -lpthread -lrt -ldl -lnetfilter_queue -lnavl
    ifeq ($(ARCH),x86_64)
      LIBPATH = -Lsrc/vineyard/lib64
    else
      LIBPATH = -Lsrc/vineyard/lib
  endif
else
  $(error ERROR: Unsupported platform '$(SYSTEM)')
endif

CXXFLAGS = $(DEBUG) $(GPROF) $(SPEED) -Wall -pthread

CXXFLAGS += -DVERSION=\"$(VERSION)\"
CXXFLAGS += -DBUILDID=\"$(BUILDID)\"
CXXFLAGS += -DPLATFORM=\"$(PLATFORM)\"

OBJFILES := $(patsubst src/%.cpp,src/%.o,$(wildcard src/*.cpp))

classd : $(OBJFILES)
	$(CXX) $(DEBUG) $(GPROF) $(SPEED) $(OBJFILES) $(LIBPATH) $(LIBFILES) -o classd

$(OBJFILES) : Makefile src/*.h

clean : force
	rm -f classd
	rm -f src/*.o

force :

