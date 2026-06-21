CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared

all: libaes.so

libaes.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f libaes.so

install: all
	cp libaes.so ../../