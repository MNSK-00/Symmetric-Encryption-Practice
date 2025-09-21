import os
from base64 import b64encode, b64decode
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import socket

BLOCK_SIZE = 8

def read_hex_file_as_bytes(file_path):
    """지정된 파일에서 16진수 문자열을 읽어 바이트로 변환합니다."""
    with open(file_path, 'r') as f:
        hex_str = f.read().strip()
    return bytes.fromhex(hex_str)

def get_key_and_iv(root_path):
    """공유 디렉토리에서 키와 IV를 읽어옵니다."""
    keys_dir = os.path.join(root_path, 'keys')
    k1 = read_hex_file_as_bytes(os.path.join(keys_dir, 'K1.txt'))
    k2 = read_hex_file_as_bytes(os.path.join(keys_dir, 'K2.txt'))
    iv = read_hex_file_as_bytes(os.path.join(keys_dir, 'IV.txt'))
    
    # 2-Key 3DES는 16바이트 키를 사용합니다.
    key = k1 + k2
    return key, iv

def encrypt_3des_cbc(plaintext, key, iv):
    """3DES CBC 모드로 평문을 암호화하고 Base64로 인코딩합니다."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_text)
    return b64encode(ciphertext)

def encrypt_3des_ecb(plaintext, key):
    """3DES ECB 모드로 평문을 암호화하고 Base64로 인코딩합니다."""
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_text)
    return b64encode(ciphertext)

def decrypt_3des_cbc(ciphertext_b64, key, iv):
    """Base64로 인코딩된 3DES CBC 암호문을 복호화합니다."""
    ciphertext = b64decode(ciphertext_b64)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, BLOCK_SIZE)

def decrypt_3des_ecb(ciphertext_b64, key):
    """Base64로 인코딩된 3DES ECB 암호문을 복호화합니다."""
    ciphertext = b64decode(ciphertext_b64)
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, BLOCK_SIZE)

def send_prefixed_data(sock, data):
    """데이터 길이를 먼저 보내고 실제 데이터를 전송합니다."""
    try:
        data_len = len(data).to_bytes(4, 'big')
        sock.sendall(data_len + data)
    except (BrokenPipeError, ConnectionResetError):
        # 원격 호스트가 연결을 닫았을 때 발생하는 오류를 처리합니다.
        print("Error: Could not send data. Connection is closed.")
        raise

def receive_prefixed_data(sock):
    """데이터 길이를 먼저 받고, 해당 길이만큼의 실제 데이터를 수신합니다."""
    try:
        len_bytes = sock.recv(4)
        if not len_bytes:
            return b'' # 연결이 정상적으로 종료됨
        
        data_len = int.from_bytes(len_bytes, 'big')
        
        if data_len > 10 * 1024 * 1024: # 10MB 한도
            raise ValueError("Data size exceeds 10MB limit.")

        data = b''
        while len(data) < data_len:
            packet = sock.recv(data_len - len(data))
            if not packet:
                # 데이터 수신 중 예기치 않게 연결이 끊김
                raise ConnectionAbortedError("Connection lost while receiving data.")
            data += packet
        return data
    except (ConnectionResetError, TimeoutError):
        # 원격 호스트가 연결을 강제로 닫거나 타임아웃 발생 시 처리
        raise ConnectionAbortedError("Connection was forcibly closed by the remote host.")