CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror
LDFLAGS = -ldl

TARGET = cryptum
SOURCES = src/main.cpp src/crypto/keygen.cpp src/plugin/plugin_loader.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

clean-all: clean
	rm -f *.so
	cd crypto_plugins/dummy && make clean

.PHONY: all clean clean-all
