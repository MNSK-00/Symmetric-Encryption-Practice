import socket
import argparse
import os
import threading
from app.utils import (
    get_key_and_iv,
    encrypt_3des_cbc,
    encrypt_3des_ecb,
    send_prefixed_data,
    receive_prefixed_data
)

def handle_client(client_socket, client_address, root_path):
    """클라이언트 연결을 처리하고 암호문을 전송합니다."""
    print(f"Connection accepted from {client_address}")
    try:
        # 1. 클라이언트로부터 암호화 모드 수신
        mode_data = receive_prefixed_data(client_socket)
        if not mode_data:
            print(f"Client {client_address} disconnected before sending mode.")
            return

        mode = mode_data.decode('utf-8').upper()
        print(f"Received mode request: {mode}")

        # 2. 공유 파일에서 키, IV, 평문 읽기
        key, iv = get_key_and_iv(root_path)
        plaintext_path = os.path.join(root_path, 'data', 'plaintext.txt')
        with open(plaintext_path, 'rb') as f:
            plaintext = f.read()

        # 3. 요청된 모드로 암호화
        if mode == 'CBC':
            ciphertext_b64 = encrypt_3des_cbc(plaintext, key, iv)
        elif mode == 'ECB':
            ciphertext_b64 = encrypt_3des_ecb(plaintext, key)
        else:
            raise ValueError(f"Invalid mode received: {mode}")

        # 4. 암호문을 클라이언트로 전송
        send_prefixed_data(client_socket, ciphertext_b64)
        print(f"Sent encrypted data to {client_address} using {mode} mode.")

    except (ValueError, FileNotFoundError, ConnectionAbortedError) as e:
        print(f"Error handling client {client_address}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred with client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection closed for {client_address}")

def run_server(port, root_path):
    """서버를 시작하고 클라이언트 연결을 기다립니다."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"Python server is running on port {port}...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            # 각 클라이언트를 별도의 스레드에서 처리
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, client_address, root_path)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Python 3DES Encryption Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--root", type=str, default="/app/shared", help="Path to shared directory")
    
    args = parser.parse_args()
    run_server(args.port, args.root)