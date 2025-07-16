#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // ��� memcpy
#include <stdexcept>

// ���������� Crypto++ ��� RC6
#include <rc6.h>
#include <modes.h>
#include <filters.h>
#include <secblock.h>
#include <osrng.h> // ��� AutoSeededRandomPool

// ��������� ��� �������� �����
struct PasswordEntry {
    std::string website;
    std::string password;
    int id;

    PasswordEntry(const std::string& ws, const std::string& pwd, int i)
        : website(ws), password(pwd), id(i) {}
};

// ��������� ���������� ����� � IV
void generateKeyAndIV(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
}

// ���������� ������ � ������� RC6 (CBC �����)
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
        std::cerr << "������ ����������: " << e.what() << std::endl;
        return "";
    }
    return ciphertext;
}

// ������������ ������ � ������� RC6 (CBC �����)
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
        std::cerr << "������ ������������: " << e.what() << std::endl;
        return "";
    }
    return decrypted;
}

// ������ � �������� ���� (� ����������� RC6)
void writeToBinaryFile(const std::string& filename, const std::vector<PasswordEntry>& entries,
    const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "������: �� ������� ������� ���� ��� ������!" << std::endl;
        return;
    }

    // ������� ���������� IV (����� ����� ����� ���� ������������)
    outFile.write(reinterpret_cast<const char*>(iv.BytePtr()), iv.size());

    for (const auto& entry : entries) {
        // ������� ������
        std::string encryptedPassword = encryptRC6(entry.password, key, iv);
        if (encryptedPassword.empty()) {
            std::cerr << "������: �� ������� ����������� ������!" << std::endl;
            continue;
        }

        // ���������� ����� ����� � ��� ����
        size_t websiteLen = entry.website.size();
        outFile.write(reinterpret_cast<const char*>(&websiteLen), sizeof(websiteLen));
        outFile.write(entry.website.c_str(), websiteLen);

        // ���������� ����� �������������� ������ � ��� ������
        size_t passwordLen = encryptedPassword.size();
        outFile.write(reinterpret_cast<const char*>(&passwordLen), sizeof(passwordLen));
        outFile.write(encryptedPassword.c_str(), passwordLen);

        // ���������� ID
        outFile.write(reinterpret_cast<const char*>(&entry.id), sizeof(entry.id));
    }

    outFile.close();
    std::cout << "������ ������� �������� � ����: " << filename << std::endl;
}

// ������ �� ��������� ����� (� ������������ RC6)
std::vector<PasswordEntry> readFromBinaryFile(const std::string& filename, const CryptoPP::SecByteBlock& key) {
    std::vector<PasswordEntry> entries;
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cerr << "������: �� ������� ������� ���� ��� ������!" << std::endl;
        return entries;
    }

    // ������ IV (�� ������� ������)
    CryptoPP::SecByteBlock iv(CryptoPP::RC6::BLOCKSIZE);
    inFile.read(reinterpret_cast<char*>(iv.BytePtr()), iv.size());

    while (true) {
        // ������ ����� �����
        size_t websiteLen;
        inFile.read(reinterpret_cast<char*>(&websiteLen), sizeof(websiteLen));
        if (inFile.eof()) break;

        // ������ ����
        std::string website(websiteLen, '\0');
        inFile.read(&website[0], websiteLen);

        // ������ ����� �������������� ������
        size_t passwordLen;
        inFile.read(reinterpret_cast<char*>(&passwordLen), sizeof(passwordLen));

        // ������ ������������� ������
        std::string encryptedPassword(passwordLen, '\0');
        inFile.read(&encryptedPassword[0], passwordLen);

        // �������������� ������
        std::string decryptedPassword = decryptRC6(encryptedPassword, key, iv);
        if (decryptedPassword.empty()) {
            std::cerr << "������: �� ������� ������������ ������!" << std::endl;
            continue;
        }

        // ������ ID
        int id;
        inFile.read(reinterpret_cast<char*>(&id), sizeof(id));

        entries.emplace_back(website, decryptedPassword, id);
    }

    inFile.close();
    std::cout << "������ ������� ��������� �� �����: " << filename << std::endl;
    return entries;
}

int main() {
    // ���������� ���� � IV
    setlocale(LC_ALL, "RU");
    CryptoPP::SecByteBlock key(32); // 256-������ ����
    CryptoPP::SecByteBlock iv(CryptoPP::RC6::BLOCKSIZE); // ������ ����� RC6 (16 ����)
    generateKeyAndIV(key, iv);

    // ������ ������
    std::vector<PasswordEntry> passwords = {
        PasswordEntry("google.com", "MySuperPass123!", 1),
        PasswordEntry("github.com", "qwerty789", 2),
        PasswordEntry("bank.com", "SuperSecret456", 3),
        PasswordEntry("gitlab.com_yiaro4840", "dividends_2345", 4),
        PasswordEntry("LTS22_yiaro", "greatwill", 5)
    };

    // ���������� � ���� (� ����������� RC6)
    writeToBinaryFile("passwords_rc6.bin", passwords, key, iv);

    // ������ �� ����� (� ������������ RC6)
    std::vector<PasswordEntry> loadedPasswords = readFromBinaryFile("passwords_rc6.bin", key);

    // ������� ���������
    std::cout << "\n����������� ������:\n";
    for (const auto& entry : loadedPasswords) {
        std::cout << "ID: " << entry.id
            << " | ����: " << entry.website
            << " | ������: " << entry.password << std::endl;
    }

    return 0;
}