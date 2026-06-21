#include "../../src/plugin/plugin_interface.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <cstdint>

static std::vector<uint8_t> atbash_encrypt_decrypt(const uint8_t* data, size_t size) 
{
    std::vector<uint8_t> result(data, data + size);
    
    for (size_t i = 0; i < size; i++) 
    {
        char c = static_cast<char>(result[i]);
        
        if (c >= 'A' && c <= 'Z') 
        {
            result[i] = static_cast<uint8_t>('Z' - (c - 'A'));
        } 
        else if (c >= 'a' && c <= 'z') 
        {
            result[i] = static_cast<uint8_t>('z' - (c - 'a'));
        }
    }
    
    return result;
}

static AlgorithmInfo info = {
    "atbash",
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
    if (key.size != 0) 
    {
        std::cerr << "Atbash: Key should be empty (no key needed)" << std::endl;
        return -1;
    }
    
    if (output->size < input.size) 
    {
        std::cerr << "Atbash: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::vector<uint8_t> result = atbash_encrypt_decrypt(input.data, input.size);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) 
{
    if (key.size != 0) 
    {
        std::cerr << "Atbash: Key should be empty (no key needed)" << std::endl;
        return -1;
    }
    
    if (output->size < input.size) 
    {
        std::cerr << "Atbash: Output buffer too small" << std::endl;
        return -1;
    }
    
    std::vector<uint8_t> result = atbash_encrypt_decrypt(input.data, input.size);
    
    memcpy(output->data, result.data(), result.size());
    output->size = result.size();
    
    return 0;
}