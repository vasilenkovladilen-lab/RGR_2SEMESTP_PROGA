#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include <string>
#include <memory>
#include <functional>
#include "plugin_interface.h"

// Кросс-платформенный загрузчик динамических библиотек
class PluginLoader {
public:
    PluginLoader();
    ~PluginLoader();
    
    // Загрузить библиотеку по имени алгоритма
    bool load_plugin(const std::string& algorithm_name);
    
    // Получить информацию об алгоритме
    const AlgorithmInfo* get_algorithm_info() const;
    
    // Получить размер выходного буфера
    size_t get_output_size(size_t input_size, int operation_type) const;
    
    // Выполнить шифрование
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) const;
    
    // Выполнить расшифрование
    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) const;
    
    // Проверить, загружен ли плагин
    bool is_loaded() const { return loaded; }
    
    // Получить имя алгоритма
    std::string get_algorithm_name() const;
    
private:
    void* handle;  // дескриптор библиотеки (void* для кросс-платформенности)
    bool loaded;
    
    // Указатели на функции из библиотеки
    const AlgorithmInfo* (*info_func)();
    size_t (*size_func)(size_t, int);
    int (*encrypt_func)(ConstBuffer, ConstBuffer, MutBuffer*);
    int (*decrypt_func)(ConstBuffer, ConstBuffer, MutBuffer*);
    
    // Формирование имени файла библиотеки в зависимости от ОС
    std::string get_library_filename(const std::string& algorithm_name);
};

#endif
