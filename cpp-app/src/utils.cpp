#include "utils.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

using namespace std;

// --- 데이터 송수신 ---

void send_prefixed_data(int sock, const string& data)
{
    uint32_t len = htonl(data.length());
    if (send(sock, &len, sizeof(len), 0) == -1)
    {
        throw runtime_error("Failed to send data length.");
    }
    if (send(sock, data.c_str(), data.length(), 0) == -1)
    {
        throw runtime_error("Failed to send data.");
    }
}

string receive_prefixed_data(int sock)
{
    uint32_t len;
    ssize_t bytes_received = recv(sock, &len, sizeof(len), 0);
    if (bytes_received <= 0)
    {
        return ""; // 연결 종료 또는 오류
    }

    len = ntohl(len);
    if (len > 10 * 1024 * 1024)
    {
        throw runtime_error("Data size exceeds 10MB limit.");
    }

    string data(len, '\0');
    bytes_received = recv(sock, &data[0], len, MSG_WAITALL);
    if (bytes_received != static_cast<ssize_t>(len))
    {
        throw runtime_error("Failed to receive complete data.");
    }
    return data;
}

// --- 파일 I/O ---

vector<unsigned char> read_file(const string& path)
{
    ifstream file(path, ios::binary);
    if (!file)
    {
        throw runtime_error("Failed to open file: " + path);
    }
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

vector<unsigned char> read_hex_file(const string& path)
{
    ifstream file(path);
    if (!file)
    {
        throw runtime_error("Failed to open hex file: " + path);
    }
    
    string hex_str;
    file >> hex_str;
    
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex_str.length(); i += 2)
    {
        string byteString = hex_str.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// --- Base64 인코딩/디코딩 ---

string base64_encode(const vector<unsigned char>& data)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

vector<unsigned char> base64_decode(const string& encoded_string)
{
    BIO *bio, *b64;
    vector<unsigned char> decoded(encoded_string.length());
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded_string.c_str(), -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_length = BIO_read(bio, decoded.data(), encoded_string.length());
    BIO_free_all(bio);
    
    decoded.resize(decoded_length);
    return decoded;
}

// --- 3DES 암호화/복호화 ---

vector<unsigned char> encrypt_3des_cbc(const vector<unsigned char>& plaintext, const unsigned char* key, const unsigned char* iv)
{
    EVP_CIPHER_CTX *ctx;
    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        throw runtime_error("Encrypt: CTX new failed.");
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
    {
        throw runtime_error("Encrypt: Init failed.");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
    {
        throw runtime_error("Encrypt: Update failed.");
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        throw runtime_error("Encrypt: Final failed.");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

vector<unsigned char> encrypt_3des_ecb(const vector<unsigned char>& plaintext, const unsigned char* key)
{
    EVP_CIPHER_CTX *ctx;
    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        throw runtime_error("Encrypt: CTX new failed.");
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key, NULL))
    {
        throw runtime_error("Encrypt: Init failed.");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
    {
        throw runtime_error("Encrypt: Update failed.");
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        throw runtime_error("Encrypt: Final failed.");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

vector<unsigned char> decrypt_3des_cbc(const vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv)
{
    EVP_CIPHER_CTX *ctx;
    vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        throw runtime_error("Decrypt: CTX new failed.");
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
    {
        throw runtime_error("Decrypt: Init failed.");
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
    {
        throw runtime_error("Decrypt: Update failed.");
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        throw runtime_error("Decrypt: Final failed.");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}

vector<unsigned char> decrypt_3des_ecb(const vector<unsigned char>& ciphertext, const unsigned char* key)
{
    EVP_CIPHER_CTX *ctx;
    vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        throw runtime_error("Decrypt: CTX new failed.");
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key, NULL))
    {
        throw runtime_error("Decrypt: Init failed.");
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
    {
        throw runtime_error("Decrypt: Update failed.");
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        throw runtime_error("Decrypt: Final failed.");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}