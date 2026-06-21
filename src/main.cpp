#include <iostream>
#include <string>
#include <getopt.h>
#include <vector>
#include <fstream>
#include <cctype>
#include <algorithm>
#include "crypto/keygen.h"
#include "plugin/plugin_loader.h"

// ============================================================
// КЛАССИЧЕСКИЕ ШИФРЫ (для текста)
// ============================================================

std::string atbash_encrypt(const std::string& text) {
    std::string result = text;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = char(base + 25 - (c - base));
        }
    }
    return result;
}

std::string gronsfeld_encrypt(const std::string& text, const std::string& key) {
    std::string result = text;
    size_t key_pos = 0;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = key[key_pos % key.length()] - '0';
            c = char(base + (c - base + shift) % 26);
            key_pos++;
        }
    }
    return result;
}

std::string gronsfeld_decrypt(const std::string& text, const std::string& key) {
    std::string result = text;
    size_t key_pos = 0;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = key[key_pos % key.length()] - '0';
            c = char(base + (c - base - shift + 26) % 26);
            key_pos++;
        }
    }
    return result;
}

std::string vigenere_encrypt(const std::string& text, const std::string& key) {
    std::string result = text;
    size_t key_pos = 0;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            char k_base = isupper(key[key_pos % key.length()]) ? 'A' : 'a';
            int shift = (key[key_pos % key.length()] - k_base);
            c = char(base + (c - base + shift) % 26);
            key_pos++;
        }
    }
    return result;
}

std::string vigenere_decrypt(const std::string& text, const std::string& key) {
    std::string result = text;
    size_t key_pos = 0;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            char k_base = isupper(key[key_pos % key.length()]) ? 'A' : 'a';
            int shift = (key[key_pos % key.length()] - k_base);
            c = char(base + (c - base - shift + 26) % 26);
            key_pos++;
        }
    }
    return result;
}

// ============================================================
// УТИЛИТЫ
// ============================================================

void clear_screen() {
    system("clear");
}

void wait_for_enter() {
    std::cout << "\nНажмите Enter для продолжения...";
    std::cin.ignore();
    std::cin.get();
}

// ============================================================
// ENUM CLASS (UpperCamelCase по ТЗ п. 4.4.4.3)
// ============================================================

enum class Algorithm {
    Atbash = 1,
    Gronsfeld = 2,
    Vigenere = 3,
    Gost = 4,
    Blowfish = 5,
    Aes = 6
};

// ============================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================

Algorithm selected_algo = Algorithm::Gost;

struct AlgoInfo {
    std::string name;
    std::string plugin_name;
};

AlgoInfo algo_infos[] = {
    {"", ""},
    {"Шифр Атбаш", ""},
    {"Шифр Гронсфельда", ""},
    {"Шифр Виженера", ""},
    {"ГОСТ 28147-89", "gost"},
    {"Blowfish", "blowfish"},
    {"AES-128", "aes"}
};

// ============================================================
// МЕНЮ
// ============================================================

void print_header() {
    std::cout << "==========================================\n";
    std::cout << "     CRYPTUM - Multi-Algo Cryptotool\n";
    std::cout << "==========================================\n";
    std::cout << "Текущий алгоритм: " << algo_infos[static_cast<int>(selected_algo)].name << "\n";
    std::cout << "==========================================\n";
}

void print_algorithms() {
    clear_screen();
    std::cout << "=== ВЫБОР АЛГОРИТМА ===\n";
    std::cout << "1. Шифр Атбаш\n";
    std::cout << "2. Шифр Гронсфельда\n";
    std::cout << "3. Шифр Виженера\n";
    std::cout << "4. ГОСТ 28147-89\n";
    std::cout << "5. Blowfish\n";
    std::cout << "6. AES-128\n";
    std::cout << "Выберите алгоритм (1-6): ";
}

bool is_classic_algorithm(Algorithm algo) {
    return algo == Algorithm::Atbash ||
           algo == Algorithm::Gronsfeld ||
           algo == Algorithm::Vigenere;
}

bool is_plugin_algorithm(Algorithm algo) {
    return algo == Algorithm::Gost ||
           algo == Algorithm::Blowfish ||
           algo == Algorithm::Aes;
}

std::string get_plugin_name(Algorithm algo) {
    return algo_infos[static_cast<int>(algo)].plugin_name;
}

void text_operation() {
    clear_screen();
    print_header();
    std::cout << "1. Зашифровать текст\n";
    std::cout << "2. Расшифровать текст\n";
    std::cout << "Ваш выбор: ";
    
    int choice;
    std::cin >> choice;
    std::cin.ignore();
    
    std::string text, key;
    std::cout << "Введите текст: ";
    std::getline(std::cin, text);
    
    std::string result;
    
    if (selected_algo == Algorithm::Atbash) {
        result = atbash_encrypt(text);
    }
    else if (selected_algo == Algorithm::Gronsfeld) {
        std::cout << "Введите ключ (цифры, например 12345): ";
        std::getline(std::cin, key);
        if (choice == 1) result = gronsfeld_encrypt(text, key);
        else result = gronsfeld_decrypt(text, key);
    }
    else if (selected_algo == Algorithm::Vigenere) {
        std::cout << "Введите ключ-слово: ";
        std::getline(std::cin, key);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (choice == 1) result = vigenere_encrypt(text, key);
        else result = vigenere_decrypt(text, key);
    }
    else {
        std::cout << "Этот алгоритм работает только с ФАЙЛАМИ.\n";
        std::cout << "Используйте пункт меню 2 для работы с файлами.\n";
        wait_for_enter();
        return;
    }
    
    clear_screen();
    print_header();
    std::cout << "=== РЕЗУЛЬТАТ ===\n";
    std::cout << (choice == 1 ? "ЗАШИФРОВАННЫЙ" : "РАСШИФРОВАННЫЙ") << " ТЕКСТ:\n";
    std::cout << result << "\n";
    wait_for_enter();
}

void file_operation_with_plugin(const std::string& plugin_name, int choice) {
    std::string key_file, input_file, output_file;
    std::cout << "Введите путь к файлу с ключом: ";
    std::getline(std::cin, key_file);
    std::cout << "Введите путь к входному файлу: ";
    std::getline(std::cin, input_file);
    std::cout << "Введите путь к выходному файлу: ";
    std::getline(std::cin, output_file);
    
    std::ifstream kf(key_file, std::ios::binary);
    if (!kf) {
        std::cerr << "Ошибка: не удалось открыть ключ\n";
        wait_for_enter();
        return;
    }
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
    kf.close();
    
    std::ifstream inf(input_file, std::ios::binary);
    if (!inf) {
        std::cerr << "Ошибка: не удалось открыть входной файл\n";
        wait_for_enter();
        return;
    }
    std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(inf)), std::istreambuf_iterator<char>());
    inf.close();
    std::cerr << "Загружено " << input_data.size() << " байт\n";
    
    PluginLoader loader;
    if (!loader.load_plugin(plugin_name)) {
        std::cerr << "Ошибка: не удалось загрузить плагин " << plugin_name << "\n";
        wait_for_enter();
        return;
    }
    
    const AlgorithmInfo* info = loader.get_algorithm_info();
    if (info && key.size() != info->key_size) {
        std::cerr << "Ошибка: неверный размер ключа (ожидается " << info->key_size << " байт)\n";
        wait_for_enter();
        return;
    }
    
    int op_type = (choice == 1) ? OP_ENCRYPT : OP_DECRYPT;
    size_t output_size = loader.get_output_size(input_data.size(), op_type);
    
    std::vector<uint8_t> output_data(output_size);
    MutBuffer out_buf = { output_data.data(), output_data.size() };
    ConstBuffer key_buf = { key.data(), key.size() };
    ConstBuffer in_buf = { input_data.data(), input_data.size() };
    
    int result;
    if (choice == 1) {
        result = loader.encrypt(key_buf, in_buf, &out_buf);
    } else {
        result = loader.decrypt(key_buf, in_buf, &out_buf);
    }
    
    if (result != 0) {
        std::cerr << "Ошибка: операция не удалась (код " << result << ")\n";
        wait_for_enter();
        return;
    }
    
    output_data.resize(out_buf.size);
    std::ofstream outf(output_file, std::ios::binary);
    outf.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
    outf.close();
    
    std::cout << "Результат сохранён в: " << output_file << "\n";
    wait_for_enter();
}

void file_operation() {
    clear_screen();
    print_header();
    std::cout << "1. Зашифровать файл\n";
    std::cout << "2. Расшифровать файл\n";
    std::cout << "Ваш выбор: ";
    
    int choice;
    std::cin >> choice;
    std::cin.ignore();
    
    if (is_classic_algorithm(selected_algo)) {
        std::string input_file, output_file, key;
        std::cout << "Введите путь к входному файлу: ";
        std::getline(std::cin, input_file);
        std::cout << "Введите путь к выходному файлу: ";
        std::getline(std::cin, output_file);
        
        std::ifstream in(input_file);
        if (!in) {
            std::cerr << "Ошибка: не удалось открыть файл\n";
            wait_for_enter();
            return;
        }
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        
        std::string result;
        if (selected_algo == Algorithm::Atbash) {
            result = atbash_encrypt(text);
        }
        else if (selected_algo == Algorithm::Gronsfeld) {
            std::cout << "Введите ключ (цифры): ";
            std::getline(std::cin, key);
            if (choice == 1) result = gronsfeld_encrypt(text, key);
            else result = gronsfeld_decrypt(text, key);
        }
        else if (selected_algo == Algorithm::Vigenere) {
            std::cout << "Введите ключ-слово: ";
            std::getline(std::cin, key);
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            if (choice == 1) result = vigenere_encrypt(text, key);
            else result = vigenere_decrypt(text, key);
        }
        
        std::ofstream out(output_file);
        out << result;
        out.close();
        std::cout << "Результат сохранён в: " << output_file << "\n";
        wait_for_enter();
        return;
    }
    
    if (is_plugin_algorithm(selected_algo)) {
        std::string plugin_name = get_plugin_name(selected_algo);
        if (!plugin_name.empty()) {
            file_operation_with_plugin(plugin_name, choice);
        }
    } else {
        std::cout << "Алгоритм не поддерживает работу с файлами\n";
        wait_for_enter();
    }
}

void generate_key_menu() {
    clear_screen();
    print_header();
    std::cout << "=== ГЕНЕРАТОР КЛЮЧЕЙ ===\n";
    
    if (!is_plugin_algorithm(selected_algo)) {
        std::cout << "Генерация ключей доступна только для ГОСТ, Blowfish, AES\n";
        wait_for_enter();
        return;
    }
    
    std::string plugin_name = get_plugin_name(selected_algo);
    std::string save_file;
    std::cout << "Введите имя файла для сохранения ключа: ";
    std::cin >> save_file;
    std::cin.ignore();
    
    int result = generate_key(plugin_name, save_file, false, true);
    if (result == 0) {
        std::cout << "Ключ сгенерирован и сохранён в: " << save_file << "\n";
    }
    wait_for_enter();
}

void list_algorithms() {
    clear_screen();
    std::cout << "=== ДОСТУПНЫЕ АЛГОРИТМЫ ===\n\n";
    std::cout << "1. Шифр Атбаш        - классический шифр подстановки\n";
    std::cout << "2. Шифр Гронсфельда  - шифр с числовым ключом\n";
    std::cout << "3. Шифр Виженера     - шифр с текстовым ключом\n";
    std::cout << "4. ГОСТ 28147-89     - блочный шифр (256-bit)\n";
    std::cout << "5. Blowfish          - блочный шифр (128-bit)\n";
    std::cout << "6. AES-128           - блочный шифр (128-bit)\n\n";
    wait_for_enter();
}

void select_algorithm() {
    clear_screen();
    print_algorithms();
    int choice;
    std::cin >> choice;
    std::cin.ignore();
    
    switch (choice) {
        case 1: selected_algo = Algorithm::Atbash; break;
        case 2: selected_algo = Algorithm::Gronsfeld; break;
        case 3: selected_algo = Algorithm::Vigenere; break;
        case 4: selected_algo = Algorithm::Gost; break;
        case 5: selected_algo = Algorithm::Blowfish; break;
        case 6: selected_algo = Algorithm::Aes; break;
        default:
            std::cout << "\nНеверный выбор!\n";
            wait_for_enter();
            return;
    }
    
    std::cout << "\nВыбран алгоритм: " << algo_infos[static_cast<int>(selected_algo)].name << "\n";
    wait_for_enter();
}

// ============================================================
// CLI РЕЖИМ
// ============================================================

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Multi-Algo Cryptotool - шифрование и расшифрование данных\n\n"
              << "Supported algorithms:\n"
              << "  gost       - ГОСТ 28147-89 (256-bit key, 64-bit block)\n"
              << "  blowfish   - Blowfish (32-448 bit key, 64-bit block)\n"
              << "  aes        - AES-128 (128-bit key, 128-bit block)\n"
              << "  dummy      - Тестовый алгоритм (для отладки)\n\n"
              << "Options:\n"
              << "  -h, --help                 показать эту справку\n"
              << "  -a, --algorithm ALGO       gost | blowfish | aes | dummy\n"
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
              << "  " << program_name << " -a aes -m encrypt -k key.bin -i data.txt -o data.enc\n";
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

int run_cli_mode(int argc, char* argv[]) {
    if (argc == 1) {
        return -1;
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

    if (!algorithm.empty() && algorithm != "gost" && algorithm != "blowfish" && algorithm != "aes" && algorithm != "dummy") {
        std::cerr << "Error: Unsupported algorithm '" << algorithm << "'\n";
        std::cerr << "Supported: gost, blowfish, aes, dummy\n";
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

// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[]) {
    if (argc > 1) {
        int result = run_cli_mode(argc, argv);
        if (result != -1) {
            return result;
        }
    }
    
    while (true) {
        clear_screen();
        print_header();
        std::cout << "1. Шифрование/расшифрование ТЕКСТА\n";
        std::cout << "2. Шифрование/расшифрование ФАЙЛА\n";
        std::cout << "3. Генерация ключа\n";
        std::cout << "4. Список доступных алгоритмов\n";
        std::cout << "5. Выбрать алгоритм\n";
        std::cout << "6. Выход\n";
        std::cout << "==========================================\n";
        std::cout << "Ваш выбор: ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: text_operation(); break;
            case 2: file_operation(); break;
            case 3: generate_key_menu(); break;
            case 4: list_algorithms(); break;
            case 5: select_algorithm(); break;
            case 6:
                std::cout << "До свидания!\n";
                return 0;
            default:
                std::cout << "Неверный выбор!\n";
                wait_for_enter();
        }
    }
    
    return 0;
}
