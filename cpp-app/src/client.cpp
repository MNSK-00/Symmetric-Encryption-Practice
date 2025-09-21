#include "utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <filesystem>
#include <netdb.h>
#include <cstring>
#include <argp.h>

using namespace std;
namespace fs = std::filesystem;

struct arguments
{
    string host;
    int port;
    string root_path;
    string mode;
};

static struct argp_option options[] = {
    {"host", 'h', "HOST", 0, "Host name of the server"},
    {"port", 'p', "PORT", 0, "Port to connect to"},
    {"root", 'r', "ROOT", 0, "Root directory for shared files"},
    {"mode", 'm', "MODE", 0, "Encryption mode (CBC or ECB)"},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;
    switch (key)
    {
        case 'h': arguments->host = arg; break;
        case 'p': arguments->port = stoi(arg); break;
        case 'r': arguments->root_path = arg; break;
        case 'm': arguments->mode = arg; break;
        default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, "A C++ 3DES encryption client."};

void run_client(const string& host, int port, const string& root_path, const string& mode)
{
    int client_socket = -1;
    try
    {
        struct addrinfo hints, *servinfo, *p;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        string port_str = to_string(port);
        int rv;
        if ((rv = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &servinfo)) != 0)
        {
            throw runtime_error("getaddrinfo error: " + string(gai_strerror(rv)));
        }

        for(p = servinfo; p != NULL; p = p->ai_next)
        {
            if ((client_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) continue;
            if (connect(client_socket, p->ai_addr, p->ai_addrlen) != -1) break;
            close(client_socket);
        }
        freeaddrinfo(servinfo);

        if (p == NULL)
        {
            throw runtime_error("Failed to connect to host: " + host);
        }
        
        cout << "Connected to server at " << host << ":" << port << endl;

        // 1. 암호문 요청을 위해 모드 전송
        string normalized_mode = mode;
        for(auto &c : normalized_mode) c = toupper(c);
        send_prefixed_data(client_socket, normalized_mode);
        cout << "Requested ciphertext using " << normalized_mode << " mode." << endl;
        cout << "Waiting for encrypted response from server..." << endl;

        // 2. 서버로부터 암호문 수신
        string ciphertext_b64 = receive_prefixed_data(client_socket);
        if (ciphertext_b64.empty())
        {
            throw runtime_error("Server closed the connection without sending data.");
        }

        // 3. 공유 파일에서 키, IV, 원본 평문 읽기
        fs::path key_path = fs::path(root_path) / "keys";
        auto k1_vec = read_hex_file((key_path / "K1.txt").string());
        auto k2_vec = read_hex_file((key_path / "K2.txt").string());
        
        vector<unsigned char> full_key_vec;
        full_key_vec.insert(full_key_vec.end(), k1_vec.begin(), k1_vec.end());
        full_key_vec.insert(full_key_vec.end(), k2_vec.begin(), k2_vec.end());

        fs::path data_path = fs::path(root_path) / "data" / "plaintext.txt";
        auto original_plaintext_vec = read_file(data_path.string());

        // 4. 수신한 암호문 복호화
        auto ciphertext = base64_decode(ciphertext_b64);
        vector<unsigned char> decrypted_text;
        if (normalized_mode == "CBC")
        {
            auto iv_vec = read_hex_file((key_path / "IV.txt").string());
            decrypted_text = decrypt_3des_cbc(ciphertext, full_key_vec.data(), iv_vec.data());
        }
        else if (normalized_mode == "ECB")
        {
            decrypted_text = decrypt_3des_ecb(ciphertext, full_key_vec.data());
        }
        else
        {
            throw runtime_error("Invalid mode specified: " + normalized_mode);
        }

        // 5. 복호화 결과와 원본 평문 비교하여 검증
        if (original_plaintext_vec == decrypted_text)
        {
            cout << "Verification Success: Decrypted text matches the original plaintext." << endl;
        }
        else
        {
            cout << "Verification Failed: Decrypted text does not match the original plaintext." << endl;
        }
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
    }

    if (client_socket != -1)
    {
        close(client_socket);
    }
    cout << "Connection closed." << endl;
}


int main(int argc, char *argv[])
{
    struct arguments arguments;
    arguments.host = "python-app";
    arguments.port = 5000;
    arguments.root_path = "/app/shared";
    arguments.mode = "CBC";
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    run_client(arguments.host, arguments.port, arguments.root_path, arguments.mode);
    return 0;
}