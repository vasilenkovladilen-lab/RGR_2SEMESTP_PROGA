#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>
#include <vector>
#include <cstdint>

int generate_key(const std::string& algorithm, 
                 const std::string& save_file, 
                 bool write_to_stdout,
                 bool show_hex);

// Функции генерации ключей для каждого алгоритма
std::vector<uint8_t> generate_gost_key();
std::vector<uint8_t> generate_blowfish_key(size_t size = 16);
std::vector<uint8_t> generate_aes_key();
std::vector<uint8_t> generate_gronsfeld_key();
std::vector<uint8_t> generate_vigenere_key();

void secure_zero(uint8_t* data, size_t size);

#endif