CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared

all: libgost.so

libgost.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f libgost.so

install: all
	cp libgost.so ../../
