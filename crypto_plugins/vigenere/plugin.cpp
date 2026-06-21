#include "../../src/plugin/plugin_interface.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <cstdint>

static std::string parse_key(const uint8_t* key_data, size_t key_size) 
{
    std::string key_str;
    for (size_t i = 0; i < key_size; i++) {
        char c = static_cast<char>(key_data[i]);
        if (c >= 'A' && c <= 'Z') {
            key_str.push_back(c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            key_str.push_back(c - 'a');
        }
    }
    return key_str;
}

static std::vector<uint8_t> vigenere_encrypt(const uint8_t* data, size_t size, const std::string& key) 
{
    if (key.empty()) {
        return std::vector<uint8_t>(data, data + size);
    }
    
    std::vector<uint8_t> result(data, data + size);
    size_t key_len = key.size();
    size_t key_pos = 0;
    
    for (size_t i = 0; i < size; i++) {
        char c = static_cast<char>(result[i]);
        
        if (c >= 'A' && c <= 'Z') {
            int shift = key[key_pos % key_len];
            result[i] = static_cast<uint8_t>('A' + (c - 'A' + shift) % 26);
            key_pos++;
        } else if (c >= 'a' && c <= 'z') {
            int shift = key[key_pos % key_len];
            result[i] = static_cast<uint8_t>('a' + (c - 'a' + shift) % 26);
            key_pos++;
        }
    }
    
    return result;
}

static std::vector<uint8_t> vigenere_decrypt(const uint8_t* data, size_t size, const std::string& key) 
{
    if (key.empty()) {
        return std::vector<uint8_t>(data, data + size);
    }
    
    std::vector<uint8_t> result(data, data + size);
    size_t key_len = key.size();
    size_t key_pos = 0;
    
    for (size_t i = 0; i < size; i++) {
        char c = static_cast<char>(result[i]);
        
        if (c >= 'A' && c <= 'Z') {
            int shift = key[key_pos % key_len];
            result[i] = static_cast<uint8_t>('A' + (c - 'A' - shift + 26) % 26);
            key_pos++;
        } else if (c >= 'a' && c <= 'z') {
            int shift = key[key_pos % key_len];
            result[i] = static_cast<uint8_t>('a' + (c - 'a' - shift + 26) % 26);
            key_pos++;
        }
    }
    
    return result;
}

static AlgorithmInfo info = {
    "vigenere",
    0,
    0
};

extern "C" const AlgorithmInfo* get_algorithm_info() 
{
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int) 
{
    return input_size;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) 
{
    if (key.size == 0) {
        std::cerr << "Vigenere: Key cannot be empty" << std::endl;
        return -1;
    }
    
    if (output->size < input.size) {
        std::cerr << "Vigenere: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::string key_str = parse_key(key.data, key.size);
    if (key_str.empty()) {
        std::cerr << "Vigenere: Key must contain letters (A-Z, a-z)" << std::endl;
        return -1;
    }
    
    std::vector<uint8_t> result = vigenere_encrypt(input.data, input.size, key_str);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) 
{
    if (key.size == 0) {
        std::cerr << "Vigenere: Key cannot be empty" << std::endl;
        return -1;
    }
    
    if (output->size < input.size) {
        std::cerr << "Vigenere: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::string key_str = parse_key(key.data, key.size);
    if (key_str.empty()) {
        std::cerr << "Vigenere: Key must contain letters (A-Z, a-z)" << std::endl;
        return -1;
    }
    
    std::vector<uint8_t> result = vigenere_decrypt(input.data, input.size, key_str);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}