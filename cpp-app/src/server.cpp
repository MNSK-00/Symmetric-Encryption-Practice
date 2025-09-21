#include "utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <filesystem>
#include <thread>
#include <argp.h>

using namespace std;
namespace fs = std::filesystem;

struct arguments
{
    int port;
    string root_path;
};

static struct argp_option options[] = {
    {"port", 'p', "PORT", 0, "Port to listen on"},
    {"root", 'r', "ROOT", 0, "Root directory for shared files"},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = (struct arguments *)state->input;
    switch (key)
    {
        case 'p': arguments->port = stoi(arg); break;
        case 'r': arguments->root_path = arg; break;
        default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, "A C++ 3DES encryption server."};

void handle_connection(int client_socket, const string& root_path)
{
    try
    {
        // 1. 클라이언트로부터 암호화 모드 수신
        string mode = receive_prefixed_data(client_socket);
        if (mode.empty())
        {
            cerr << "Client disconnected before sending mode." << endl;
            close(client_socket);
            return;
        }
        cout << "Received mode request: " << mode << endl;

        // 2. 공유 파일에서 키, IV, 평문 읽기
        fs::path key_path = fs::path(root_path) / "keys";
        auto k1_vec = read_hex_file((key_path / "K1.txt").string());
        auto k2_vec = read_hex_file((key_path / "K2.txt").string());
        
        vector<unsigned char> full_key_vec;
        full_key_vec.insert(full_key_vec.end(), k1_vec.begin(), k1_vec.end());
        full_key_vec.insert(full_key_vec.end(), k2_vec.begin(), k2_vec.end());

        fs::path data_path = fs::path(root_path) / "data" / "plaintext.txt";
        auto plaintext_vec = read_file(data_path.string());
        
        // 3. 요청된 모드로 암호화
        vector<unsigned char> ciphertext;
        if (mode == "CBC")
        {
            auto iv_vec = read_hex_file((key_path / "IV.txt").string());
            ciphertext = encrypt_3des_cbc(plaintext_vec, full_key_vec.data(), iv_vec.data());
        }
        else if (mode == "ECB")
        {
            ciphertext = encrypt_3des_ecb(plaintext_vec, full_key_vec.data());
        }
        else
        {
            throw runtime_error("Invalid mode received: " + mode);
        }

        // 4. 암호문을 Base64로 인코딩하여 클라이언트로 전송
        string ciphertext_b64 = base64_encode(ciphertext);
        send_prefixed_data(client_socket, ciphertext_b64);
        cout << "Sent encrypted data to client using " << mode << " mode." << endl;
    }
    catch (const exception& e)
    {
        cerr << "Error handling connection: " << e.what() << endl;
    }

    // 안정적인 종료를 위해 shutdown 사용
    if (shutdown(client_socket, SHUT_WR) < 0)
    {
        perror("shutdown failed");
    }
    close(client_socket);
    cout << "Client connection closed." << endl;
}

int main(int argc, char *argv[])
{
    struct arguments arguments;
    arguments.port = 5001;
    arguments.root_path = "/app/shared";
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        cerr << "Socket creation failed" << endl;
        return -1;
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        cerr << "setsockopt failed" << endl;
        close(server_fd);
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(arguments.port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        cerr << "Bind failed" << endl;
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 5) < 0)
    {
        cerr << "Listen failed" << endl;
        close(server_fd);
        return -1;
    }

    cout << "C++ Server is running on port " << arguments.port << "..." << endl;

    while (true)
    {
        int client_socket;
        socklen_t addrlen = sizeof(address);
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0)
        {
            cerr << "Accept failed" << endl;
            continue; 
        }
        cout << "Connection accepted." << endl;
        
        thread(handle_connection, client_socket, arguments.root_path).detach();
    }

    close(server_fd);
    return 0;
}