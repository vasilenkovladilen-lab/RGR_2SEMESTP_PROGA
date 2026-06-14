#include <iostream>
#include <string>
#include <getopt.h>

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Multi-Algo Cryptotool - шифрование и расшифрование данных\n\n"
              << "Supported algorithms:\n"
              << "  gost       - ГОСТ 28147-89 (256-bit key, 64-bit block)\n"
              << "  blowfish   - Blowfish (32-448 bit key, 64-bit block)\n\n"
              << "Options:\n"
              << "  -h, --help                 показать эту справку\n"
              << "  -a, --algorithm ALGO       gost | blowfish\n"
              << "  -m, --mode MODE            encrypt | decrypt | generate-key\n"
              << "  -k, --key FILE             ключ из файла\n"
              << "  -i, --input FILE           входной файл\n"
              << "  -o, --output FILE          выходной файл\n"
              << "      --generate-key         сгенерировать ключ\n"
              << "      --save-key FILE        сохранить ключ в файл\n"
              << "      --write-key            записать ключ в stdout\n\n"
              << "Examples:\n"
              << "  " << program_name << " --help\n"
              << "  " << program_name << " -a gost -m generate-key --save-key key.bin\n"
              << "  " << program_name << " -a blowfish -m encrypt -k key.bin -i data -o data.enc\n"
              << "  " << program_name << " -a gost -m decrypt -k key.bin -i data.enc -o data\n";
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
        {0, 0, 0, 0}
    };

    std::string algorithm, mode, key_file, input_file, output_file;
    bool gen_key = false;
    std::string save_key_file;
    bool write_key = false;

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
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    // Валидация алгоритма
    if (!algorithm.empty() && algorithm != "gost" && algorithm != "blowfish") {
        std::cerr << "Error: Unsupported algorithm '" << algorithm << "'\n";
        std::cerr << "Supported: gost, blowfish\n";
        return 1;
    }

    // Валидация режима
    if (!mode.empty() && mode != "encrypt" && mode != "decrypt" && mode != "generate-key") {
        std::cerr << "Error: Unsupported mode '" << mode << "'\n";
        std::cerr << "Supported: encrypt, decrypt, generate-key\n";
        return 1;
    }

    std::cout << "=== Parameters ===\n";
    if (!algorithm.empty()) std::cout << "Algorithm: " << algorithm << "\n";
    if (!mode.empty())      std::cout << "Mode: " << mode << "\n";
    if (!key_file.empty())  std::cout << "Key file: " << key_file << "\n";
    if (!input_file.empty()) std::cout << "Input file: " << input_file << "\n";
    if (!output_file.empty()) std::cout << "Output file: " << output_file << "\n";
    if (gen_key)            std::cout << "Generate key: yes\n";
    if (!save_key_file.empty()) std::cout << "Save key to: " << save_key_file << "\n";
    if (write_key)          std::cout << "Write key to stdout: yes\n";

    return 0;
}
