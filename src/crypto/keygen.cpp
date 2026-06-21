#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

class SecureRandom {
private:
    int fd;
public:
    SecureRandom() {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            std::cerr << "Error: Cannot open /dev/urandom" << std::endl;
            exit(1);
        }
    }
    
    ~SecureRandom() {
        if (fd >= 0) close(fd);
    }
    
    void fill_bytes(uint8_t* buffer, size_t size) {
        size_t bytes_read = 0;
        while (bytes_read < size) {
            ssize_t result = read(fd, buffer + bytes_read, size - bytes_read);
            if (result <= 0) {
                std::cerr << "Error: Failed to read from /dev/urandom" << std::endl;
                exit(1);
            }
            bytes_read += result;
        }
    }
};

void print_key_hex(const std::vector<uint8_t>& key) {
    std::cerr << "Key (hex): ";
    for (size_t i = 0; i < key.size(); i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 8 == 0 && i + 1 < key.size()) {
            std::cerr << " ";
        }
    }
    std::cerr << std::endl;
}

std::vector<uint8_t> generate_gost_key() {
    std::vector<uint8_t> key(32);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> generate_blowfish_key(size_t size = 16) {
    if (size < 4) size = 4;
    if (size > 56) size = 56;
    
    std::vector<uint8_t> key(size);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> generate_aes_key() {
    std::vector<uint8_t> key(16);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> generate_gronsfeld_key() {
    std::vector<uint8_t> key(8);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    for (size_t i = 0; i < key.size(); i++) {
        key[i] = (key[i] % 10) + '0';
    }
    return key;
}

std::vector<uint8_t> generate_vigenere_key() {
    std::vector<uint8_t> key(16);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    for (size_t i = 0; i < key.size(); i++) {
        key[i] = (key[i] % 26) + 'A';
    }
    return key;
}

void secure_zero(uint8_t* data, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

bool save_key_to_file(const std::vector<uint8_t>& key, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file for writing: " << filename << std::endl;
        return false;
    }
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
    if (!file) {
        std::cerr << "Error: Failed to write key to file: " << filename << std::endl;
        return false;
    }
    std::cerr << "Key saved to: " << filename << " (" << key.size() << " bytes)" << std::endl;
    return true;
}

void write_key_to_stdout(const std::vector<uint8_t>& key) {
    std::cout.write(reinterpret_cast<const char*>(key.data()), key.size());
    std::cout.flush();
    std::cerr << "Key written to stdout (" << key.size() << " bytes)" << std::endl;
}

int generate_key(const std::string& algorithm, 
                 const std::string& save_file, 
                 bool write_to_stdout,
                 bool show_hex) {
    
    std::vector<uint8_t> key;
    
    if (algorithm == "gost") {
        key = generate_gost_key();
        std::cerr << "Generated GOST 28147-89 key: " << key.size() << " bytes" << std::endl;
    } 
    else if (algorithm == "blowfish") {
        key = generate_blowfish_key(16);
        std::cerr << "Generated Blowfish key: " << key.size() << " bytes" << std::endl;
    }
    else if (algorithm == "aes") {
        key = generate_aes_key();
        std::cerr << "Generated AES key: " << key.size() << " bytes (128-bit)" << std::endl;
    }
    else if (algorithm == "gronsfeld") {
        key = generate_gronsfeld_key();
        std::cerr << "Generated Gronsfeld key: " << key.size() << " bytes (digits)" << std::endl;
    }
    else if (algorithm == "vigenere") {
        key = generate_vigenere_key();
        std::cerr << "Generated Vigenere key: " << key.size() << " bytes (letters)" << std::endl;
    }
    else if (algorithm == "dummy") {
        key = std::vector<uint8_t>(16, 0x42);
        std::cerr << "Generated DUMMY key: " << key.size() << " bytes" << std::endl;
    }
    else if (algorithm == "atbash") {
        std::cerr << "Atbash does not need a key (no key generated)" << std::endl;
        if (show_hex) {
            std::cerr << "Atbash: no key" << std::endl;
        }
        if (!save_file.empty()) {
            std::cerr << "Warning: Atbash doesn't need a key, ignoring --save-key" << std::endl;
        }
        if (write_to_stdout) {
            std::cerr << "Warning: Atbash doesn't need a key, ignoring --write-key" << std::endl;
        }
        return 0;
    }
    else {
        std::cerr << "Error: Unknown algorithm for key generation: " << algorithm << std::endl;
        return 1;
    }
    
    if (show_hex) {
        print_key_hex(key);
    }
    
    if (write_to_stdout) {
        write_key_to_stdout(key);
    }
    
    if (!save_file.empty()) {
        if (!save_key_to_file(key, save_file)) {
            return 1;
        }
    }
    
    if (!write_to_stdout && save_file.empty() && !key.empty()) {
        std::cerr << "Error: No output method specified for key (use --save-key or --write-key)" << std::endl;
        return 1;
    }
    
    secure_zero(key.data(), key.size());
    
    return 0;
}