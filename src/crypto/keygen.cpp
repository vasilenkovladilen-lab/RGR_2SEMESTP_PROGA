#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>

// Криптостойкий генератор случайных чисел
class SecureRandom {
private:
    std::random_device rd;
    std::mt19937_64 gen;
    std::uniform_int_distribution<uint8_t> dist;

public:
    SecureRandom() : gen(rd()) {}
    
    uint8_t get_byte() {
        return dist(gen);
    }
    
    void fill_bytes(uint8_t* buffer, size_t size) {
        for (size_t i = 0; i < size; i++) {
            buffer[i] = get_byte();
        }
    }
};

// Генерация ключа для ГОСТ 28147-89 (32 байта = 256 бит)
std::vector<uint8_t> generate_gost_key() {
    std::vector<uint8_t> key(32);  // 256 бит
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    return key;
}

// Генерация ключа для Blowfish (16 байт по умолчанию, можно менять)
std::vector<uint8_t> generate_blowfish_key(size_t size = 16) {
    if (size < 4) size = 4;
    if (size > 56) size = 56;
    
    std::vector<uint8_t> key(size);
    SecureRandom rng;
    rng.fill_bytes(key.data(), key.size());
    return key;
}

// Сохранение ключа в файл
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

// Вывод ключа в stdout (для pipe)
void write_key_to_stdout(const std::vector<uint8_t>& key) {
    std::cout.write(reinterpret_cast<const char*>(key.data()), key.size());
    std::cerr << "Key written to stdout (" << key.size() << " bytes)" << std::endl;
}

// Функция для использования из main
int generate_key(const std::string& algorithm, 
                 const std::string& save_file, 
                 bool write_to_stdout) {
    
    std::vector<uint8_t> key;
    
    if (algorithm == "gost") {
        key = generate_gost_key();
        std::cerr << "Generated GOST 28147-89 key: " << key.size() << " bytes" << std::endl;
    } 
    else if (algorithm == "blowfish") {
        key = generate_blowfish_key(16);  // 128 бит по умолчанию
        std::cerr << "Generated Blowfish key: " << key.size() << " bytes" << std::endl;
    } 
    else {
        std::cerr << "Error: Unknown algorithm for key generation: " << algorithm << std::endl;
        return 1;
    }
    
    // Сохранение или вывод
    if (write_to_stdout) {
        write_key_to_stdout(key);
    }
    
    if (!save_file.empty()) {
        if (!save_key_to_file(key, save_file)) {
            return 1;
        }
    }
    
    if (!write_to_stdout && save_file.empty()) {
        std::cerr << "Error: No output method specified for key (use --save-key or --write-key)" << std::endl;
        return 1;
    }
    
    return 0;
}
