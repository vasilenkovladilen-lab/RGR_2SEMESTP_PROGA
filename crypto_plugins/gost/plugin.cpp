#include "../../src/plugin/plugin_interface.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>

// ============================================================
// ГОСТ 28147-89 — полная реализация
// ============================================================

// S-блоки (стандарт idn)
static const uint8_t S_BOX[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 3, 15, 4, 2, 11, 6, 9, 8, 14, 5, 12, 0},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
};

static inline uint32_t bytes_to_uint32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | 
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void uint32_to_bytes(uint32_t x, uint8_t* b) {
    b[0] = (x >> 24) & 0xFF;
    b[1] = (x >> 16) & 0xFF;
    b[2] = (x >> 8) & 0xFF;
    b[3] = x & 0xFF;
}

static uint32_t gost_sbox_transform(uint32_t x) {
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t val = (x >> (4 * i)) & 0x0F;
        result |= ((uint32_t)S_BOX[i][val] << (4 * i));
    }
    return result;
}

static uint32_t gost_round_function(uint32_t x, uint32_t key) {
    return gost_sbox_transform((x + key) & 0xFFFFFFFF);
}

static void gost_encrypt_block(uint32_t* left, uint32_t* right, const uint32_t* key) {
    // 24 раунда с повторением ключей
    for (int i = 0; i < 24; i++) {
        uint32_t tmp = *left ^ gost_round_function(*right, key[i % 8]);
        *left = *right;
        *right = tmp;
    }
    // Последние 8 раундов в обратном порядке
    for (int i = 7; i >= 0; i--) {
        uint32_t tmp = *left ^ gost_round_function(*right, key[i]);
        *left = *right;
        *right = tmp;
    }
}

static void gost_decrypt_block(uint32_t* left, uint32_t* right, const uint32_t* key) {
    // Расшифрование в обратном порядке
    for (int i = 0; i < 8; i++) {
        uint32_t tmp = *left ^ gost_round_function(*right, key[i]);
        *left = *right;
        *right = tmp;
    }
    for (int i = 23; i >= 0; i--) {
        uint32_t tmp = *left ^ gost_round_function(*right, key[i % 8]);
        *left = *right;
        *right = tmp;
    }
}

static void gost_ecb_encrypt(uint8_t* data, size_t len, const uint8_t* key) {
    uint32_t k[8];
    for (int i = 0; i < 8; i++) {
        k[i] = bytes_to_uint32(key + i * 4);
    }
    
    for (size_t i = 0; i < len; i += 8) {
        uint32_t left = bytes_to_uint32(data + i);
        uint32_t right = bytes_to_uint32(data + i + 4);
        gost_encrypt_block(&left, &right, k);
        uint32_to_bytes(left, data + i);
        uint32_to_bytes(right, data + i + 4);
    }
}

static void gost_ecb_decrypt(uint8_t* data, size_t len, const uint8_t* key) {
    uint32_t k[8];
    for (int i = 0; i < 8; i++) {
        k[i] = bytes_to_uint32(key + i * 4);
    }
    
    for (size_t i = 0; i < len; i += 8) {
        uint32_t left = bytes_to_uint32(data + i);
        uint32_t right = bytes_to_uint32(data + i + 4);
        gost_decrypt_block(&left, &right, k);
        uint32_to_bytes(left, data + i);
        uint32_to_bytes(right, data + i + 4);
    }
}

// ============================================================
// PKCS#7 паддинг
// ============================================================

static std::vector<uint8_t> add_padding(const uint8_t* data, size_t size, size_t block_size) {
    size_t padding_len = block_size - (size % block_size);
    if (padding_len == 0) padding_len = block_size;
    
    std::vector<uint8_t> result(data, data + size);
    result.resize(size + padding_len);
    for (size_t i = 0; i < padding_len; i++) {
        result[size + i] = static_cast<uint8_t>(padding_len);
    }
    return result;
}

static bool remove_padding(std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    
    uint8_t padding_len = data.back();
    if (padding_len == 0 || padding_len > data.size() || padding_len > 8) {
        return false;
    }
    
    for (size_t i = data.size() - padding_len; i < data.size(); i++) {
        if (data[i] != padding_len) return false;
    }
    
    data.resize(data.size() - padding_len);
    return true;
}

// ============================================================
// Интерфейс плагина
// ============================================================

static AlgorithmInfo info = {
    "gost",
    32,
    8
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
    if (key.size != 32) {
        std::cerr << "GOST: Invalid key size (expected 32 bytes)" << std::endl;
        return -1;
    }
    
    std::vector<uint8_t> padded = add_padding(input.data, input.size, 8);
    
    if (output->size < padded.size()) {
        std::cerr << "GOST: Output buffer too small" << std::endl;
        return -1;
    }
    
    memcpy(output->data, padded.data(), padded.size());
    gost_ecb_encrypt(output->data, padded.size(), key.data);
    output->size = padded.size();
    
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size != 32) {
        std::cerr << "GOST: Invalid key size (expected 32 bytes)" << std::endl;
        return -1;
    }
    
    if (input.size % 8 != 0) {
        std::cerr << "GOST: Input size not multiple of block size" << std::endl;
        return -1;
    }
    
    if (output->size < input.size) {
        std::cerr << "GOST: Output buffer too small" << std::endl;
        return -1;
    }
    
    memcpy(output->data, input.data, input.size);
    gost_ecb_decrypt(output->data, input.size, key.data);
    
    std::vector<uint8_t> result(output->data, output->data + input.size);
    if (!remove_padding(result)) {
        std::cerr << "GOST: Invalid padding" << std::endl;
        return -1;
    }
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}
