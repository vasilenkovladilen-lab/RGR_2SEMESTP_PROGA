#include "../../src/plugin/plugin_interface.h"
#include <iostream>
#include <cstring>

static AlgorithmInfo info = {
    "dummy",
    16,    // key_size
    8      // block_size
};

extern "C" const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    // Для теста: выходной размер = входной + 16 байт overhead
    return input_size + 16;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    std::cerr << "DUMMY PLUGIN: Encrypt called" << std::endl;
    std::cerr << "Key size: " << key.size << std::endl;
    std::cerr << "Input size: " << input.size << std::endl;
    
    if (output->size < input.size + 16) {
        return -1;  // буфер太小
    }
    
    // Просто копируем входные данные (не настоящее шифрование!)
    memcpy(output->data, input.data, input.size);
    // Добавляем маркер в конец
    memset(output->data + input.size, 0xFF, 16);
    
    output->size = input.size + 16;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    std::cerr << "DUMMY PLUGIN: Decrypt called" << std::endl;
    
    if (input.size < 16) {
        return -1;
    }
    
    size_t plain_size = input.size - 16;
    if (output->size < plain_size) {
        return -1;
    }
    
    memcpy(output->data, input.data, plain_size);
    output->size = plain_size;
    return 0;
}
