#pragma once

#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cstring>
#include <format>
#include <sstream>

// Функция для конвертации строки в hex
inline std::string stringToHex(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

// Функция для конвертации hex обратно в строку
inline std::string hexToString(const std::string& hex) {
    std::string output;
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        output.push_back(byte);
    }
    return output;
}

class Crypto {
public:
    Crypto() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    
    ~Crypto() {
        EVP_cleanup();
        ERR_free_strings();
    }

    std::string encrypt(const std::string& plaintext, const std::string& password) {
        unsigned char salt[16];
        if (!RAND_bytes(salt, sizeof(salt))) {
            printErrors();
            return "";
        }

        unsigned char key[32], iv[12];
        if (!deriveKeyAndIV(password, salt, key, iv)) {
            return "";
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            printErrors();
            return "";
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        int len;
        unsigned char ciphertext_buffer[plaintext.length() + EVP_CIPHER_CTX_block_size(ctx)];
        if (EVP_EncryptUpdate(ctx, ciphertext_buffer, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        int ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext_buffer + len, &len) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        ciphertext_len += len;

        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        EVP_CIPHER_CTX_free(ctx);
        std::string ciphertext;
        
        ciphertext.assign(reinterpret_cast<const char*>(salt), sizeof(salt));
        ciphertext.append(reinterpret_cast<const char*>(iv), sizeof(iv));
        ciphertext.append(reinterpret_cast<const char*>(ciphertext_buffer), ciphertext_len);
        ciphertext.append(reinterpret_cast<const char*>(tag), sizeof(tag));
        return ciphertext;
    }

    std::string decrypt(const std::string& ciphertext, const std::string& password) {
        std::string plaintext;
        
        if (ciphertext.length() < 44) { // salt (16) + iv (12) + tag (16)
            std::cerr << "Ciphertext too short." << std::endl;
            return "";
        }

        const unsigned char* salt = reinterpret_cast<const unsigned char*>(ciphertext.c_str());
        const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.c_str() + 16);
        const unsigned char* tag = reinterpret_cast<const unsigned char*>(ciphertext.c_str() + ciphertext.length() - 16);
        const unsigned char* enc_data = reinterpret_cast<const unsigned char*>(ciphertext.c_str() + 28);
        size_t enc_data_len = ciphertext.length() - 44;

        unsigned char key[32];
        if (!deriveKeyAndIV(password, salt, key, nullptr)) {
            return "";
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            printErrors();
            return "";
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        int len;
        unsigned char plaintext_buffer[enc_data_len];
        if (EVP_DecryptUpdate(ctx, plaintext_buffer, &len, enc_data, enc_data_len) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        int plaintext_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        if (EVP_DecryptFinal_ex(ctx, plaintext_buffer + len, &len) != 1) {
            printErrors();
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        plaintext.assign(reinterpret_cast<const char*>(plaintext_buffer), plaintext_len);
        return plaintext;
    }

private:
    bool deriveKeyAndIV(const std::string& password, const unsigned char* salt, unsigned char* key, unsigned char* iv) {
        const EVP_MD* dgst = EVP_sha256();
        if (!dgst) {
            printErrors();
            return "";
        }

        if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, 16, 500000, dgst, 32, key)) {
            printErrors();
            return "";
        }

        if (iv) {
            if (!RAND_bytes(iv, 12)) {
                printErrors();
                return "";
            }
        }

        return true;
    }

    void printErrors() {
        ERR_print_errors_fp(stderr);
    }
};


// int main() {
//     Database db;
//     Crypto crypto;
    
//     std::string site;
//     std::string e_site;
    
//     std::string login;
//     std::string e_login;
    
//     std::string password;
//     std::string e_password;
    
//     std::string encrypt_password = "eWrMaekqPhdyo3yoR4u2FQ==";
    
//     if (!crypto.encrypt(site, encrypt_password, e_site)) std::cout << "Сайт не зашифровался\n";
//     if (!crypto.encrypt(login, encrypt_password, e_login)) std::cout << "логин не зашифровался\n";
//     if (!crypto.encrypt(password, encrypt_password, e_password)) std::cout << "пароль не зашифровался\n";    
    
//     std::string execute_code = std::format("INSERT INTO data(site, login, password) VALUES(\"{}\", \"{}\", \"{}\");", e_site, e_login, e_password);
    
//     // std::cout << db.exec(execute_code.c_str()) << std::endl;
    
//     std::cout << db.exec("select * from data;");
    
//     // if (crypto.encrypt(plaintext, password, ciphertext)) {
//     //     std::cout << "Encrypted: " << ciphertext << std::endl;
        
//     //     std::string decryptedtext;
//     //     if (crypto.decrypt(ciphertext, password, decryptedtext)) {
//     //         std::cout << "Decrypted: " << decryptedtext << std::endl;
//     //     } else {
//     //         std::cerr << "Decryption failed." << std::endl;
//     //     }
//     // } else {
//     //     std::cerr << "Encryption failed." << std::endl;
//     // }
    
//     return 0;
// }
