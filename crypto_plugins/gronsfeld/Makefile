CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared

all: libgronsfeld.so

libgronsfeld.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f libgronsfeld.so

install: all
	cp libgronsfeld.so ../../