#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <filesystem>

// 데이터 송수신 함수
void send_prefixed_data(int sock, const std::string& data);
std::string receive_prefixed_data(int sock);

// 파일 I/O 함수
std::vector<unsigned char> read_file(const std::string& path);
std::vector<unsigned char> read_hex_file(const std::string& path);

// Base64 인코딩/디코딩 함수
std::string base64_encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64_decode(const std::string& encoded_string);

// 3DES 암호화/복호화 함수
std::vector<unsigned char> encrypt_3des_cbc(const std::vector<unsigned char>& plaintext, const unsigned char* key, const unsigned char* iv);
std::vector<unsigned char> encrypt_3des_ecb(const std::vector<unsigned char>& plaintext, const unsigned char* key);
std::vector<unsigned char> decrypt_3des_cbc(const std::vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv);
std::vector<unsigned char> decrypt_3des_ecb(const std::vector<unsigned char>& ciphertext, const unsigned char* key);

#endif // UTILS_HPP