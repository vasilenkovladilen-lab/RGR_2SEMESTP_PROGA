#ifndef PLUGIN_INTERFACE_H
#define PLUGIN_INTERFACE_H

#include <cstdint>
#include <cstddef>

// Структуры для передачи данных (по ТЗ п. 4.4.7.1)
struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

// Типы операций для get_output_size
enum OperationType {
    OP_ENCRYPT = 1,
    OP_DECRYPT = 2
};

// Структура с информацией об алгоритме (по ТЗ п. 4.4.7.1)
struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;        // размер ключа в байтах
    size_t block_size;      // размер блока в байтах (для PKCS#7)
};

// Функции, которые должна экспортировать каждая библиотека-плагин
extern "C" {
    const AlgorithmInfo* get_algorithm_info();
    size_t get_output_size(size_t input_size, int operation_type);
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
}

#endif
