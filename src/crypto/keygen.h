#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>
#include <vector>
#include <cstdint>

int generate_key(const std::string& algorithm, 
                 const std::string& save_file, 
                 bool write_to_stdout,
                 bool show_hex);  // новый параметр

void secure_zero(uint8_t* data, size_t size);

#endif
