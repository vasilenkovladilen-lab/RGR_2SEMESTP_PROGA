CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -I./src
CXXFLAGS_PLUGIN = -std=c++17 -Wall -Wextra -I./src -fPIC -shared
LDFLAGS = -ldl
LDFLAGS_PLUGIN = -ldl

TARGET = cryptum
SOURCES = src/main.cpp src/crypto/keygen.cpp src/plugin/plugin_loader.cpp
OBJECTS = $(SOURCES:.cpp=.o)

PLUGINS = gost blowfish aes atbash gronsfeld vigenere
PLUGIN_LIBS = $(addprefix libplugin_, $(addsuffix .so, $(PLUGINS)))

# Папка для плагинов
PLUGIN_DIR = algorithms

all: $(TARGET) $(PLUGIN_LIBS)
	mkdir -p $(PLUGIN_DIR)
	cp $(PLUGIN_LIBS) $(PLUGIN_DIR)/
	rm -f $(PLUGIN_LIBS)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

libplugin_%.so: crypto_plugins/%/plugin.cpp
	$(CXX) $(CXXFLAGS_PLUGIN) -o $@ $^ $(LDFLAGS_PLUGIN)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(PLUGIN_LIBS)
	rm -rf $(PLUGIN_DIR)

install: all
	mkdir -p /usr/local/bin
	cp $(TARGET) /usr/local/bin/
	mkdir -p /usr/local/lib/cryptum
	cp $(PLUGIN_DIR)/*.so /usr/local/lib/cryptum/
	@echo "Installation complete. Run 'cryptum' to use the program."

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	rm -rf /usr/local/lib/cryptum
	@echo "Uninstallation complete."

.PHONY: all clean install uninstall