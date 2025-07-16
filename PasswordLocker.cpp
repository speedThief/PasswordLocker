#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // для memcpy
#include <stdexcept>

// Подключаем Crypto++ для RC6
#include <rc6.h>
#include <modes.h>
#include <filters.h>
#include <secblock.h>
#include <osrng.h> // для AutoSeededRandomPool

// Структура для хранения данны
struct PasswordEntry {
    std::string website;
    std::string password;
    int id;

    PasswordEntry(const std::string& ws, const std::string& pwd, int i)
        : website(ws), password(pwd), id(i) {}
};

// Генерация случайного ключа и IV
void generateKeyAndIV(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
}

// Шифрование строки с помощью RC6 (CBC режим)
std::string encryptRC6(const std::string& plaintext, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::string ciphertext;
    try {
        CryptoPP::CBC_Mode<CryptoPP::RC6>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource ss(
            plaintext,
            true,
            new CryptoPP::StreamTransformationFilter(
                encryptor,
                new CryptoPP::StringSink(ciphertext)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка шифрования: " << e.what() << std::endl;
        return "";
    }
    return ciphertext;
}

// Дешифрование строки с помощью RC6 (CBC режим)
std::string decryptRC6(const std::string& ciphertext, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::string decrypted;
    try {
        CryptoPP::CBC_Mode<CryptoPP::RC6>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource ss(
            ciphertext,
            true,
            new CryptoPP::StreamTransformationFilter(
                decryptor,
                new CryptoPP::StringSink(decrypted)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка дешифрования: " << e.what() << std::endl;
        return "";
    }
    return decrypted;
}

// Запись в бинарный файл (с шифрованием RC6)
void writeToBinaryFile(const std::string& filename, const std::vector<PasswordEntry>& entries,
    const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Ошибка: Не удалось открыть файл для записи!" << std::endl;
        return;
    }

    // Сначала записываем IV (чтобы потом можно было расшифровать)
    outFile.write(reinterpret_cast<const char*>(iv.BytePtr()), iv.size());

    for (const auto& entry : entries) {
        // Шифруем пароль
        std::string encryptedPassword = encryptRC6(entry.password, key, iv);
        if (encryptedPassword.empty()) {
            std::cerr << "Ошибка: Не удалось зашифровать пароль!" << std::endl;
            continue;
        }

        // Записываем длину сайта и сам сайт
        size_t websiteLen = entry.website.size();
        outFile.write(reinterpret_cast<const char*>(&websiteLen), sizeof(websiteLen));
        outFile.write(entry.website.c_str(), websiteLen);

        // Записываем длину зашифрованного пароля и сам пароль
        size_t passwordLen = encryptedPassword.size();
        outFile.write(reinterpret_cast<const char*>(&passwordLen), sizeof(passwordLen));
        outFile.write(encryptedPassword.c_str(), passwordLen);

        // Записываем ID
        outFile.write(reinterpret_cast<const char*>(&entry.id), sizeof(entry.id));
    }

    outFile.close();
    std::cout << "Данные успешно записаны в файл: " << filename << std::endl;
}

// Чтение из бинарного файла (с расшифровкой RC6)
std::vector<PasswordEntry> readFromBinaryFile(const std::string& filename, const CryptoPP::SecByteBlock& key) {
    std::vector<PasswordEntry> entries;
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cerr << "Ошибка: Не удалось открыть файл для чтения!" << std::endl;
        return entries;
    }

    // Читаем IV (он записан первым)
    CryptoPP::SecByteBlock iv(CryptoPP::RC6::BLOCKSIZE);
    inFile.read(reinterpret_cast<char*>(iv.BytePtr()), iv.size());

    while (true) {
        // Читаем длину сайта
        size_t websiteLen;
        inFile.read(reinterpret_cast<char*>(&websiteLen), sizeof(websiteLen));
        if (inFile.eof()) break;

        // Читаем сайт
        std::string website(websiteLen, '\0');
        inFile.read(&website[0], websiteLen);

        // Читаем длину зашифрованного пароля
        size_t passwordLen;
        inFile.read(reinterpret_cast<char*>(&passwordLen), sizeof(passwordLen));

        // Читаем зашифрованный пароль
        std::string encryptedPassword(passwordLen, '\0');
        inFile.read(&encryptedPassword[0], passwordLen);

        // Расшифровываем пароль
        std::string decryptedPassword = decryptRC6(encryptedPassword, key, iv);
        if (decryptedPassword.empty()) {
            std::cerr << "Ошибка: Не удалось расшифровать пароль!" << std::endl;
            continue;
        }

        // Читаем ID
        int id;
        inFile.read(reinterpret_cast<char*>(&id), sizeof(id));

        entries.emplace_back(website, decryptedPassword, id);
    }

    inFile.close();
    std::cout << "Данные успешно прочитаны из файла: " << filename << std::endl;
    return entries;
}

int main() {
    // Генерируем ключ и IV
    setlocale(LC_ALL, "RU");
    CryptoPP::SecByteBlock key(32); // 256-битный ключ
    CryptoPP::SecByteBlock iv(CryptoPP::RC6::BLOCKSIZE); // Размер блока RC6 (16 байт)
    generateKeyAndIV(key, iv);

    // Пример данных
    std::vector<PasswordEntry> passwords = {
        PasswordEntry("google.com", "MySuperPass123!", 1),
        PasswordEntry("github.com", "qwerty789", 2),
        PasswordEntry("bank.com", "SuperSecret456", 3),
        PasswordEntry("gitlab.com_yiaro4840", "dividends_2345", 4),
        PasswordEntry("LTS22_yiaro", "greatwill", 5)
    };

    // Записываем в файл (с шифрованием RC6)
    writeToBinaryFile("passwords_rc6.bin", passwords, key, iv);

    // Читаем из файла (с расшифровкой RC6)
    std::vector<PasswordEntry> loadedPasswords = readFromBinaryFile("passwords_rc6.bin", key);

    // Выводим результат
    std::cout << "\nЗагруженные пароли:\n";
    for (const auto& entry : loadedPasswords) {
        std::cout << "ID: " << entry.id
            << " | Сайт: " << entry.website
            << " | Пароль: " << entry.password << std::endl;
    }

    return 0;
}