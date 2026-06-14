#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>
#include <vector>

int generate_key(const std::string& algorithm, 
                 const std::string& save_file, 
                 bool write_to_stdout);

#endif
