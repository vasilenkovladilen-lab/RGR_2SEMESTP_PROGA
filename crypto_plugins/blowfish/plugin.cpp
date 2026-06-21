#include "../../src/plugin/plugin_interface.h"
#include <openssl/blowfish.h>
#include <iostream>
#include <cstring>
#include <vector>

// Глобальный контекст Blowfish
static BF_KEY bf_key;

// PKCS#7 паддинг
std::vector<uint8_t> add_padding(const uint8_t* data, size_t size, size_t block_size) {
    size_t padding_len = block_size - (size % block_size);
    if (padding_len == 0) padding_len = block_size;
    
    std::vector<uint8_t> result(data, data + size);
    for (size_t i = 0; i < padding_len; i++) {
        result.push_back(static_cast<uint8_t>(padding_len));
    }
    return result;
}

bool remove_padding(std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    
    uint8_t padding_len = data.back();
    if (padding_len == 0 || padding_len > data.size() || padding_len > 255) {
        return false;
    }
    
    for (size_t i = data.size() - padding_len; i < data.size(); i++) {
        if (data[i] != padding_len) return false;
    }
    
    data.resize(data.size() - padding_len);
    return true;
}

// Метаданные алгоритма
static AlgorithmInfo info = {
    "blowfish",
    16,     // key_size (128 bit)
    8       // block_size (64 bit)
};

extern "C" const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    if (operation_type == OP_ENCRYPT) {
        size_t padding_len = 8 - (input_size % 8);
        if (padding_len == 0) padding_len = 8;
        return input_size + padding_len;
    } else {
        return input_size;
    }
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 16) {
        std::cerr << "Blowfish: Invalid key size (expected 16 bytes)" << std::endl;
        return -1;
    }
    
    // Инициализация ключа
    BF_set_key(&bf_key, key.size, key.data);
    
    // Добавляем паддинг
    std::vector<uint8_t> padded = add_padding(input.data, input.size, 8);
    
    if (output->size < padded.size()) {
        std::cerr << "Blowfish: Output buffer too small" << std::endl;
        return -1;
    }
    
    // Шифрование блоками (ECB режим)
    for (size_t i = 0; i < padded.size(); i += 8) {
        BF_ecb_encrypt(padded.data() + i, output->data + i, &bf_key, BF_ENCRYPT);
    }
    
    output->size = padded.size();
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 16) {
        std::cerr << "Blowfish: Invalid key size (expected 16 bytes)" << std::endl;
        return -1;
    }
    
    if (input.size % 8 != 0) {
        std::cerr << "Blowfish: Input size not multiple of block size" << std::endl;
        return -1;
    }
    
    // Инициализация ключа
    BF_set_key(&bf_key, key.size, key.data);
    
    if (output->size < input.size) {
        std::cerr << "Blowfish: Output buffer too small" << std::endl;
        return -1;
    }
    
    // Расшифрование
    for (size_t i = 0; i < input.size; i += 8) {
        BF_ecb_encrypt(input.data + i, output->data + i, &bf_key, BF_DECRYPT);
    }
    
    // Удаляем паддинг
    std::vector<uint8_t> result(output->data, output->data + input.size);
    if (!remove_padding(result)) {
        std::cerr << "Blowfish: Invalid padding" << std::endl;
        return -1;
    }
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}
