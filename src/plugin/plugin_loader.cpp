#include "plugin_loader.h"
#include <iostream>
#include <dlfcn.h>
#include <vector>
#include <cstdlib>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

PluginLoader::PluginLoader() : handle(nullptr), loaded(false), 
    info_func(nullptr), size_func(nullptr), encrypt_func(nullptr), decrypt_func(nullptr) {}

PluginLoader::~PluginLoader() {
    if (handle) {
        dlclose(handle);
        handle = nullptr;
    }
}

std::string get_executable_path() {
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = '\0';
        return std::string(dirname(buf));
    }
    return ".";
}

bool file_exists(const std::string& path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}

bool PluginLoader::load_plugin(const std::string& algorithm_name) {
    if (loaded) {
        std::cerr << "Plugin already loaded" << std::endl;
        return false;
    }
    
    std::string exe_dir = get_executable_path();
    
    // Ищем в разных вариантах:
    // - libplugin_atbash.so (с префиксом plugin)
    // - libatbash.so (без plugin)
    std::vector<std::string> paths = {
        exe_dir + "/algorithms/libplugin_" + algorithm_name + ".so",
        exe_dir + "/algorithms/lib" + algorithm_name + ".so",
        "./algorithms/libplugin_" + algorithm_name + ".so",
        "./algorithms/lib" + algorithm_name + ".so",
        exe_dir + "/libplugin_" + algorithm_name + ".so",
        exe_dir + "/lib" + algorithm_name + ".so",
        "./libplugin_" + algorithm_name + ".so",
        "./lib" + algorithm_name + ".so",
        "/usr/local/lib/cryptum/libplugin_" + algorithm_name + ".so",
        "/usr/local/lib/cryptum/lib" + algorithm_name + ".so"
    };
    
    for (const auto& path : paths) {
        if (!file_exists(path)) {
            continue;
        }
        
        handle = dlopen(path.c_str(), RTLD_LAZY);
        if (handle) {
            std::cerr << "Loaded plugin: " << path << std::endl;
            break;
        } else {
            std::cerr << "dlopen failed for " << path << ": " << dlerror() << std::endl;
        }
    }
    
    if (!handle) {
        std::cerr << "Failed to load plugin: " << algorithm_name << std::endl;
        std::cerr << "Searched in: " << exe_dir << "/algorithms/" << std::endl;
        return false;
    }
    
    dlerror();
    
    info_func = (const AlgorithmInfo*(*)()) dlsym(handle, "get_algorithm_info");
    const char* error = dlerror();
    if (error) {
        std::cerr << "Failed to load 'get_algorithm_info': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    size_func = (size_t(*)(size_t, int)) dlsym(handle, "get_output_size");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load 'get_output_size': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    encrypt_func = (int(*)(ConstBuffer, ConstBuffer, MutBuffer*)) dlsym(handle, "encrypt");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load 'encrypt': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    decrypt_func = (int(*)(ConstBuffer, ConstBuffer, MutBuffer*)) dlsym(handle, "decrypt");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load 'decrypt': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    loaded = true;
    
    const AlgorithmInfo* info = info_func();
    if (info) {
        std::cerr << "Algorithm: " << info->algorithm_name << std::endl;
        std::cerr << "Key size: " << info->key_size << " bytes" << std::endl;
        std::cerr << "Block size: " << info->block_size << " bytes" << std::endl;
    }
    
    return true;
}

const AlgorithmInfo* PluginLoader::get_algorithm_info() const {
    if (!loaded || !info_func) return nullptr;
    return info_func();
}

size_t PluginLoader::get_output_size(size_t input_size, int operation_type) const {
    if (!loaded || !size_func) return 0;
    return size_func(input_size, operation_type);
}

int PluginLoader::encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) const {
    if (!loaded || !encrypt_func) return -1;
    return encrypt_func(key, input, output);
}

int PluginLoader::decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) const {
    if (!loaded || !decrypt_func) return -1;
    return decrypt_func(key, input, output);
}

std::string PluginLoader::get_algorithm_name() const {
    const AlgorithmInfo* info = get_algorithm_info();
    if (info && info->algorithm_name) {
        return std::string(info->algorithm_name);
    }
    return "unknown";
}