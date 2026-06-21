#include <iostream>
#include <string>
#include <getopt.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "crypto/keygen.h"
#include "plugin/plugin_loader.h"

// ============================================================
// Enums для алгоритмов и режимов
// ============================================================

enum class Algorithm {
    GOST,
    BLOWFISH,
    AES,
    ATBASH,
    GRONSFELD,
    VIGENERE,
    UNKNOWN
};

enum class Mode {
    ENCRYPT,
    DECRYPT,
    GENERATE_KEY,
    UNKNOWN
};

static const char* PLUGIN_DIR = "./algorithms";

// ============================================================
// Проверка плагинов
// ============================================================

bool check_plugins_exist() {
    DIR* dir = opendir(PLUGIN_DIR);
    if (!dir) return false;
    
    struct dirent* entry;
    bool has_plugin = false;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.length() > 3 && name.substr(name.length() - 3) == ".so") {
            has_plugin = true;
            break;
        }
    }
    closedir(dir);
    return has_plugin;
}

bool create_plugin_directory() {
    return (mkdir(PLUGIN_DIR, 0755) == 0);
}

void print_welcome() {
    std::cout << "Добро пожаловать!" << std::endl;
    std::cout << "Загрузка алгоритмов из папки " << PLUGIN_DIR << "/..." << std::endl;
    
    if (!check_plugins_exist()) {
        if (create_plugin_directory()) {
            std::cout << "Создана папка " << PLUGIN_DIR << std::endl;
        }
        std::cout << "Поместите .so файлы алгоритмов в эту папку и перезапустите программу." << std::endl;
        std::cout << "Завершение работы." << std::endl;
        exit(0);
    }
    
    std::cout << "Найдены алгоритмы:" << std::endl;
    DIR* dir = opendir(PLUGIN_DIR);
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.length() > 3 && name.substr(name.length() - 3) == ".so") {
            std::cout << "  - " << name.substr(0, name.length() - 3) << std::endl;
        }
    }
    closedir(dir);
    std::cout << std::endl;
}

// ============================================================
// Вспомогательные функции
// ============================================================

Algorithm parse_algorithm(const std::string& algo) {
    if (algo == "gost") return Algorithm::GOST;
    if (algo == "blowfish") return Algorithm::BLOWFISH;
    if (algo == "aes") return Algorithm::AES;
    if (algo == "atbash") return Algorithm::ATBASH;
    if (algo == "gronsfeld") return Algorithm::GRONSFELD;
    if (algo == "vigenere") return Algorithm::VIGENERE;
    return Algorithm::UNKNOWN;
}

Mode parse_mode(const std::string& m) {
    if (m == "encrypt") return Mode::ENCRYPT;
    if (m == "decrypt") return Mode::DECRYPT;
    if (m == "generate-key") return Mode::GENERATE_KEY;
    return Mode::UNKNOWN;
}

bool algorithm_needs_key(Algorithm algo) {
    return algo != Algorithm::ATBASH;
}

// ============================================================
// Печать справки
// ============================================================

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Multi-Algo Cryptotool - шифрование и расшифрование данных\n\n"
              << "Supported algorithms:\n"
              << "  gost       - ГОСТ 28147-89 (256-bit key, 64-bit block)\n"
              << "  blowfish   - Blowfish (128-bit key, 64-bit block)\n"
              << "  aes        - AES-128 (128-bit key, 128-bit block)\n"
              << "  atbash     - Atbash substitution cipher (no key)\n"
              << "  gronsfeld  - Gronsfeld cipher (digit key)\n"
              << "  vigenere   - Vigenere cipher (letter key)\n\n"
              << "Options:\n"
              << "  -h, --help                 показать эту справку\n"
              << "  -a, --algorithm ALGO       gost | blowfish | aes | atbash | gronsfeld | vigenere\n"
              << "  -m, --mode MODE            encrypt | decrypt | generate-key\n"
              << "  -k, --key FILE             ключ из файла\n"
              << "  -i, --input FILE           входной файл (если не указан, чтение из stdin)\n"
              << "  -o, --output FILE          выходной файл (если не указан, вывод в stdout)\n"
              << "  -t, --text TEXT            текст для шифрования/дешифрования\n"
              << "      --generate-key         сгенерировать ключ\n"
              << "      --save-key FILE        сохранить ключ в файл\n"
              << "      --write-key            записать ключ в stdout\n"
              << "      --show-key-hex         показать ключ в hex-формате\n\n"
              << "Examples:\n"
              << "  " << program_name << " --help\n"
              << "  " << program_name << " -a gost -m generate-key --save-key key.bin --show-key-hex\n"
              << "  " << program_name << " -a blowfish -m encrypt -k key.bin -i data -o data.enc\n"
              << "  " << program_name << " -a gost -m decrypt -k key.bin -i data.enc -o data\n"
              << "  " << program_name << " -a atbash -m encrypt -t \"Hello World\"\n"
              << "  " << program_name << " -a gronsfeld -m generate-key --save-key key.txt --show-key-hex\n"
              << "  " << program_name << " -a vigenere -m encrypt -k key.txt -i data -o data.enc\n";
}

// ============================================================
// Потоковая обработка данных
// ============================================================

int process_stream(const std::string& algorithm, const std::string& mode,
                   const std::vector<uint8_t>& key,
                   std::istream& input_stream, std::ostream& output_stream) {
    
    PluginLoader loader;
    if (!loader.load_plugin(algorithm)) {
        std::cerr << "Error: Failed to load plugin for algorithm: " << algorithm << std::endl;
        return 1;
    }
    
    const AlgorithmInfo* info = loader.get_algorithm_info();
    if (info && info->key_size > 0 && key.size() != info->key_size) {
        std::cerr << "Error: Invalid key size. Expected " << info->key_size 
                  << " bytes, got " << key.size() << std::endl;
        return 1;
    }
    
    int op_type = (mode == "encrypt") ? OP_ENCRYPT : OP_DECRYPT;
    
    const size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> input_buffer(CHUNK_SIZE);
    std::vector<uint8_t> output_buffer;
    
    size_t total_read = 0;
    size_t total_written = 0;
    
    while (input_stream) {
        input_stream.read(reinterpret_cast<char*>(input_buffer.data()), CHUNK_SIZE);
        size_t bytes_read = input_stream.gcount();
        
        if (bytes_read == 0) break;
        total_read += bytes_read;
        
        size_t input_size = bytes_read;
        
        size_t output_size = loader.get_output_size(input_size, op_type);
        output_buffer.resize(output_size);
        MutBuffer out_buf = { output_buffer.data(), output_buffer.size() };
        ConstBuffer key_buf = { key.data(), key.size() };
        ConstBuffer in_buf = { input_buffer.data(), input_size };
        
        int result;
        if (mode == "encrypt") {
            result = loader.encrypt(key_buf, in_buf, &out_buf);
        } else {
            result = loader.decrypt(key_buf, in_buf, &out_buf);
        }
        
        if (result != 0) {
            std::cerr << "Error: Cryptographic operation failed" << std::endl;
            return 1;
        }
        output_buffer.resize(out_buf.size);
        
        output_stream.write(reinterpret_cast<char*>(output_buffer.data()), output_buffer.size());
        total_written += output_buffer.size();
        
        if (!output_stream) {
            std::cerr << "Error: Failed to write output" << std::endl;
            return 1;
        }
        
        std::cerr << "\rProcessed " << total_read << " bytes, output " << total_written << " bytes" << std::flush;
    }
    
    std::cerr << "\nProcessed " << total_read << " bytes, output " << total_written << " bytes" << std::endl;
    return 0;
}

// ============================================================
// Основная функция
// ============================================================

int main(int argc, char* argv[]) {
    print_welcome();
    
    if (argc == 1) {
        print_help(argv[0]);
        return 0;
    }

    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"algorithm",   required_argument, 0, 'a'},
        {"mode",        required_argument, 0, 'm'},
        {"key",         required_argument, 0, 'k'},
        {"input",       required_argument, 0, 'i'},
        {"output",      required_argument, 0, 'o'},
        {"text",        required_argument, 0, 't'},
        {"generate-key",no_argument,       0, 1000},
        {"save-key",    required_argument, 0, 1001},
        {"write-key",   no_argument,       0, 1002},
        {"show-key-hex",no_argument,       0, 1003},
        {0, 0, 0, 0}
    };

    std::string algo_str, mode_str, key_file, input_file, output_file, text_str;
    bool gen_key = false;
    std::string save_key_file;
    bool write_key = false;
    bool show_key_hex = false;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "ha:m:k:i:o:t:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'a':
                algo_str = optarg;
                break;
            case 'm':
                mode_str = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 't':
                text_str = optarg;
                break;
            case 1000:
                gen_key = true;
                break;
            case 1001:
                save_key_file = optarg;
                break;
            case 1002:
                write_key = true;
                break;
            case 1003:
                show_key_hex = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    Algorithm algorithm = parse_algorithm(algo_str);
    if (!algo_str.empty() && algorithm == Algorithm::UNKNOWN) {
        std::cerr << "Error: Unsupported algorithm '" << algo_str << "'\n";
        std::cerr << "Supported: gost, blowfish, aes, atbash, gronsfeld, vigenere\n";
        return 1;
    }

    Mode mode = parse_mode(mode_str);
    if (!mode_str.empty() && mode == Mode::UNKNOWN) {
        std::cerr << "Error: Unsupported mode '" << mode_str << "'\n";
        std::cerr << "Supported: encrypt, decrypt, generate-key\n";
        return 1;
    }

    if (mode == Mode::GENERATE_KEY || gen_key) {
        if (algorithm == Algorithm::UNKNOWN) {
            std::cerr << "Error: Algorithm required for key generation\n";
            return 1;
        }
        return generate_key(algo_str, save_key_file, write_key, show_key_hex);
    }
    
    if (mode == Mode::ENCRYPT || mode == Mode::DECRYPT) {
        if (algorithm == Algorithm::UNKNOWN) {
            std::cerr << "Error: Algorithm required for encryption/decryption\n";
            return 1;
        }
        
        if (algorithm_needs_key(algorithm) && key_file.empty()) {
            std::cerr << "Error: Key file required (--key)\n";
            return 1;
        }
        
        std::vector<uint8_t> key;
        if (algorithm_needs_key(algorithm)) {
            std::ifstream key_stream(key_file, std::ios::binary);
            if (!key_stream) {
                std::cerr << "Error: Cannot open key file: " << key_file << std::endl;
                return 1;
            }
            key_stream.seekg(0, std::ios::end);
            size_t key_size = key_stream.tellg();
            key_stream.seekg(0, std::ios::beg);
            key.resize(key_size);
            key_stream.read(reinterpret_cast<char*>(key.data()), key_size);
            key_stream.close();
            std::cerr << "Loaded key: " << key_size << " bytes" << std::endl;
        }
        
        if (input_file.empty() && text_str.empty()) {
            std::cerr << "Error: No input provided (use --input, --text, or stdin)" << std::endl;
            return 1;
        }
        
        if (!text_str.empty()) {
            std::vector<uint8_t> text_data(text_str.begin(), text_str.end());
            std::stringstream input_stream;
            input_stream.write(reinterpret_cast<const char*>(text_data.data()), text_data.size());
            
            if (output_file.empty()) {
                std::stringstream output_stream;
                int result = process_stream(algo_str, mode_str, key, input_stream, output_stream);
                if (result != 0) return result;
                std::cout << output_stream.str() << std::endl;
            } else {
                std::ofstream output_stream(output_file, std::ios::binary);
                if (!output_stream) {
                    std::cerr << "Error: Cannot open output file: " << output_file << std::endl;
                    return 1;
                }
                return process_stream(algo_str, mode_str, key, input_stream, output_stream);
            }
        } else if (!input_file.empty()) {
            std::ifstream input_stream(input_file, std::ios::binary);
            if (!input_stream) {
                std::cerr << "Error: Cannot open input file: " << input_file << std::endl;
                return 1;
            }
            
            if (output_file.empty()) {
                return process_stream(algo_str, mode_str, key, input_stream, std::cout);
            } else {
                std::ofstream output_stream(output_file, std::ios::binary);
                if (!output_stream) {
                    std::cerr << "Error: Cannot open output file: " << output_file << std::endl;
                    return 1;
                }
                return process_stream(algo_str, mode_str, key, input_stream, output_stream);
            }
        } else {
            return process_stream(algo_str, mode_str, key, std::cin, std::cout);
        }
        
        return 0;
    }
    
    if (!mode_str.empty()) {
        std::cerr << "Error: Unknown mode '" << mode_str << "'" << std::endl;
    } else {
        std::cerr << "Error: Mode not specified" << std::endl;
    }
    std::cerr << "Use --help for usage information" << std::endl;
    return 1;
}