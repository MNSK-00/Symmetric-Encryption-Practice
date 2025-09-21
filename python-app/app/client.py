import socket
import argparse
import os
from app.utils import (
    get_key_and_iv,
    decrypt_3des_cbc,
    decrypt_3des_ecb,
    send_prefixed_data,
    receive_prefixed_data
)

def run_client(host, port, root_path, mode):
    """서버에 연결하여 암호문을 요청하고, 수신한 암호문을 검증합니다."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        # 1. 암호문 요청을 위해 모드 전송
        normalized_mode = mode.upper()
        send_prefixed_data(client_socket, normalized_mode.encode('utf-8'))
        print(f"Requested ciphertext using {normalized_mode} mode.")
        print("Waiting for encrypted response from server...")

        # 2. 서버로부터 암호문 수신
        ciphertext_b64 = receive_prefixed_data(client_socket)
        if not ciphertext_b64:
            raise ConnectionAbortedError("Server closed the connection without sending data.")

        # 3. 공유 파일에서 키, IV, 원본 평문 읽기
        key, iv = get_key_and_iv(root_path)
        plaintext_path = os.path.join(root_path, 'data', 'plaintext.txt')
        with open(plaintext_path, 'rb') as f:
            original_plaintext = f.read()
        
        # 4. 수신한 암호문 복호화
        if normalized_mode == 'CBC':
            decrypted_text = decrypt_3des_cbc(ciphertext_b64, key, iv)
        elif normalized_mode == 'ECB':
            decrypted_text = decrypt_3des_ecb(ciphertext_b64, key)
        else:
            raise ValueError(f"Invalid mode specified: {normalized_mode}")

        # 5. 복호화 결과와 원본 평문 비교하여 검증
        if original_plaintext == decrypted_text:
            print("Verification Success: Decrypted text matches the original plaintext.")
        else:
            print("Verification Failed: Decrypted text does not match the original plaintext.")

    except (ConnectionRefusedError, TimeoutError):
        print(f"Error: Connection to {host}:{port} was refused. Is the server running?")
    except (ValueError, FileNotFoundError, ConnectionAbortedError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Python 3DES Encryption Client")
    parser.add_argument("--host", type=str, default='cpp-app', help="Server host name")
    parser.add_argument("--port", type=int, default=5001, help="Server port number")
    parser.add_argument("--root", type=str, default="/app/shared", help="Path to shared directory")
    parser.add_argument("--mode", type=str, choices=['CBC', 'ECB', 'cbc', 'ecb'], default='CBC', help="Encryption mode")
    
    args = parser.parse_args()
    run_client(args.host, args.port, args.root, args.mode)