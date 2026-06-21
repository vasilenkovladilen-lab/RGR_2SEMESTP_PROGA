#include <iostream>
#include <string>
#include <getopt.h>
#include <vector>
#include <fstream>
#include "crypto/keygen.h"
#include "plugin/plugin_loader.h"

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Multi-Algo Cryptotool - шифрование и расшифрование данных\n\n"
              << "Supported algorithms:\n"
              << "  gost       - ГОСТ 28147-89 (256-bit key, 64-bit block)\n"
              << "  blowfish   - Blowfish (32-448 bit key, 64-bit block)\n"
              << "  dummy      - Тестовый алгоритм (для отладки)\n\n"
              << "Options:\n"
              << "  -h, --help                 показать эту справку\n"
              << "  -a, --algorithm ALGO       gost | blowfish | dummy\n"
              << "  -m, --mode MODE            encrypt | decrypt | generate-key\n"
              << "  -k, --key FILE             ключ из файла\n"
              << "  -i, --input FILE           входной файл\n"
              << "  -o, --output FILE          выходной файл\n"
              << "      --generate-key         сгенерировать ключ\n"
              << "      --save-key FILE        сохранить ключ в файл\n"
              << "      --write-key            записать ключ в stdout\n"
              << "      --show-key-hex         показать ключ в hex-формате\n\n"
              << "Examples:\n"
              << "  " << program_name << " --help\n"
              << "  " << program_name << " -a gost -m generate-key --save-key key.bin --show-key-hex\n"
              << "  " << program_name << " -a dummy -m encrypt -k dummy_key.bin -i test.txt -o test.enc\n"
              << "  " << program_name << " -a dummy -m decrypt -k dummy_key.bin -i test.enc -o test.dec\n";
}

std::vector<uint8_t> load_key_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open key file: " << filename << std::endl;
        return {};
    }
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return key;
}

std::vector<uint8_t> load_input(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open input file: " << filename << std::endl;
        return {};
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::cerr << "Loaded " << data.size() << " bytes from " << filename << std::endl;
    return data;
}

bool save_output(const std::vector<uint8_t>& data, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open output file: " << filename << std::endl;
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    std::cerr << "Saved " << data.size() << " bytes to " << filename << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
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
        {"generate-key",no_argument,       0, 1000},
        {"save-key",    required_argument, 0, 1001},
        {"write-key",   no_argument,       0, 1002},
        {"show-key-hex",no_argument,       0, 1003},
        {0, 0, 0, 0}
    };

    std::string algorithm, mode, key_file, input_file, output_file;
    bool gen_key = false;
    std::string save_key_file;
    bool write_key = false;
    bool show_key_hex = false;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "ha:m:k:i:o:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'a':
                algorithm = optarg;
                break;
            case 'm':
                mode = optarg;
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

    if (!algorithm.empty() && algorithm != "gost" && algorithm != "blowfish" && algorithm != "dummy") {
        std::cerr << "Error: Unsupported algorithm '" << algorithm << "'\n";
        std::cerr << "Supported: gost, blowfish, dummy\n";
        return 1;
    }

    if (mode == "generate-key" || gen_key) {
        if (algorithm.empty()) {
            std::cerr << "Error: Algorithm required for key generation\n";
            return 1;
        }
        return generate_key(algorithm, save_key_file, write_key, show_key_hex);
    }
    
    if (mode == "encrypt" || mode == "decrypt") {
        if (algorithm.empty()) {
            std::cerr << "Error: Algorithm required for encryption/decryption\n";
            return 1;
        }
        
        if (key_file.empty()) {
            std::cerr << "Error: Key file required (--key)\n";
            return 1;
        }
        
        if (input_file.empty()) {
            std::cerr << "Error: Input file required (--input)\n";
            return 1;
        }
        
        if (output_file.empty()) {
            std::cerr << "Error: Output file required (--output)\n";
            return 1;
        }
        
        std::vector<uint8_t> key = load_key_from_file(key_file);
        if (key.empty()) return 1;
        
        std::vector<uint8_t> input_data = load_input(input_file);
        if (input_data.empty()) return 1;
        
        PluginLoader loader;
        if (!loader.load_plugin(algorithm)) {
            std::cerr << "Error: Failed to load plugin for algorithm: " << algorithm << std::endl;
            return 1;
        }
        
        const AlgorithmInfo* info = loader.get_algorithm_info();
        if (info && key.size() != info->key_size) {
            std::cerr << "Error: Invalid key size. Expected " << info->key_size 
                      << " bytes, got " << key.size() << std::endl;
            return 1;
        }
        
        int op_type = (mode == "encrypt") ? OP_ENCRYPT : OP_DECRYPT;
        size_t output_size = loader.get_output_size(input_data.size(), op_type);
        
        std::vector<uint8_t> output_data(output_size);
        MutBuffer out_buf = { output_data.data(), output_data.size() };
        ConstBuffer key_buf = { key.data(), key.size() };
        ConstBuffer in_buf = { input_data.data(), input_data.size() };
        
        int result;
        if (mode == "encrypt") {
            result = loader.encrypt(key_buf, in_buf, &out_buf);
        } else {
            result = loader.decrypt(key_buf, in_buf, &out_buf);
        }
        
        if (result != 0) {
            std::cerr << "Error: Cryptographic operation failed (code " << result << ")" << std::endl;
            return 1;
        }
        
        output_data.resize(out_buf.size);
        if (!save_output(output_data, output_file)) {
            return 1;
        }
        
        std::cerr << "Operation completed successfully" << std::endl;
        return 0;
    }
    
    std::cerr << "Error: Unknown mode or missing parameters. Use --help for usage." << std::endl;
    return 1;
}
