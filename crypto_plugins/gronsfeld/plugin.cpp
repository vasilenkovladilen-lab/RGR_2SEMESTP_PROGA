#include "../../src/plugin/plugin_interface.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <cstdint>

static std::vector<int> parse_key(const uint8_t* key_data, size_t key_size) {
    std::vector<int> key_digits;
    for (size_t i = 0; i < key_size; i++) {
        if (key_data[i] >= '0' && key_data[i] <= '9') {
            key_digits.push_back(key_data[i] - '0');
        }
    }
    return key_digits;
}

static std::vector<uint8_t> gronsfeld_encrypt(const uint8_t* data, size_t size, const std::vector<int>& key) {
    if (key.empty()) {
        return std::vector<uint8_t>(data, data + size);
    }
    
    std::vector<uint8_t> result(data, data + size);
    size_t key_len = key.size();
    
    for (size_t i = 0; i < size; i++) {
        char c = static_cast<char>(result[i]);
        if (c >= 'A' && c <= 'Z') {
            int shift = key[i % key_len];
            result[i] = static_cast<uint8_t>('A' + (c - 'A' + shift) % 26);
        } else if (c >= 'a' && c <= 'z') {
            int shift = key[i % key_len];
            result[i] = static_cast<uint8_t>('a' + (c - 'a' + shift) % 26);
        }
    }
    
    return result;
}

static std::vector<uint8_t> gronsfeld_decrypt(const uint8_t* data, size_t size, const std::vector<int>& key) {
    if (key.empty()) {
        return std::vector<uint8_t>(data, data + size);
    }
    
    std::vector<uint8_t> result(data, data + size);
    size_t key_len = key.size();
    
    for (size_t i = 0; i < size; i++) {
        char c = static_cast<char>(result[i]);
        if (c >= 'A' && c <= 'Z') {
            int shift = key[i % key_len];
            result[i] = static_cast<uint8_t>('A' + (c - 'A' - shift + 26) % 26);
        } else if (c >= 'a' && c <= 'z') {
            int shift = key[i % key_len];
            result[i] = static_cast<uint8_t>('a' + (c - 'a' - shift + 26) % 26);
        }
    }
    
    return result;
}

static AlgorithmInfo info = {
    "gronsfeld",
    0,
    0
};

extern "C" const AlgorithmInfo* get_algorithm_info() {
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int) {
    return input_size;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0) {
        std::cerr << "Gronsfeld: Key cannot be empty" << std::endl;
        return -1;
    }
    
    for (size_t i = 0; i < key.size; i++) {
        if (key.data[i] < '0' || key.data[i] > '9') {
            std::cerr << "Gronsfeld: Key must contain only digits (0-9)" << std::endl;
            return -1;
        }
    }
    
    if (output->size < input.size) {
        std::cerr << "Gronsfeld: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::vector<int> key_digits = parse_key(key.data, key.size);
    std::vector<uint8_t> result = gronsfeld_encrypt(input.data, input.size, key_digits);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0) {
        std::cerr << "Gronsfeld: Key cannot be empty" << std::endl;
        return -1;
    }
    
    for (size_t i = 0; i < key.size; i++) {
        if (key.data[i] < '0' || key.data[i] > '9') {
            std::cerr << "Gronsfeld: Key must contain only digits (0-9)" << std::endl;
            return -1;
        }
    }
    
    if (output->size < input.size) {
        std::cerr << "Gronsfeld: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::vector<int> key_digits = parse_key(key.data, key.size);
    std::vector<uint8_t> result = gronsfeld_decrypt(input.data, input.size, key_digits);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}