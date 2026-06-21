CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared

all: libdummy.so

libdummy.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f libdummy.so

install: all
	cp libdummy.so ../../
