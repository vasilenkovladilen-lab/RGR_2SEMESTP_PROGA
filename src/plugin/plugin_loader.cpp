#include "plugin_loader.h"
#include <iostream>
#include <dlfcn.h>  // для Linux (dlopen, dlsym, dlclose)

PluginLoader::PluginLoader() : handle(nullptr), loaded(false), 
    info_func(nullptr), size_func(nullptr), encrypt_func(nullptr), decrypt_func(nullptr) {}

PluginLoader::~PluginLoader() {
    if (handle) {
        dlclose(handle);
        handle = nullptr;
    }
}

std::string PluginLoader::get_library_filename(const std::string& algorithm_name) {
    // Для Linux: libgost.so, libblowfish.so
    // Для Windows: gost.dll, blowfish.dll (пока не реализовано, но структура готова)
    #ifdef _WIN32
        return algorithm_name + ".dll";
    #else
        return "lib" + algorithm_name + ".so";
    #endif
}

bool PluginLoader::load_plugin(const std::string& algorithm_name) {
    if (loaded) {
        std::cerr << "Plugin already loaded" << std::endl;
        return false;
    }
    
    std::string lib_path = get_library_filename(algorithm_name);
    
    // Открываем библиотеку
    handle = dlopen(lib_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Failed to load library: " << lib_path << std::endl;
        std::cerr << "Error: " << dlerror() << std::endl;
        return false;
    }
    
    // Очищаем ошибки
    dlerror();
    
    // Получаем функцию get_algorithm_info
    info_func = (const AlgorithmInfo*(*)()) dlsym(handle, "get_algorithm_info");
    const char* error = dlerror();
    if (error) {
        std::cerr << "Failed to load symbol 'get_algorithm_info': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    // Получаем функцию get_output_size
    size_func = (size_t(*)(size_t, int)) dlsym(handle, "get_output_size");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load symbol 'get_output_size': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    // Получаем функцию encrypt
    encrypt_func = (int(*)(ConstBuffer, ConstBuffer, MutBuffer*)) dlsym(handle, "encrypt");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load symbol 'encrypt': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    // Получаем функцию decrypt
    decrypt_func = (int(*)(ConstBuffer, ConstBuffer, MutBuffer*)) dlsym(handle, "decrypt");
    error = dlerror();
    if (error) {
        std::cerr << "Failed to load symbol 'decrypt': " << error << std::endl;
        dlclose(handle);
        handle = nullptr;
        return false;
    }
    
    loaded = true;
    std::cerr << "Plugin loaded successfully: " << lib_path << std::endl;
    
    // Выводим информацию об алгоритме
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
