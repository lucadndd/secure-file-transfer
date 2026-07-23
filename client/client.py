import socket
import sys
import os
import json
import struct

HOST = 'localhost'
PORT = 9000
CHUNK = 65536

def send_file(path, host = HOST, port = PORT):
    filename = os.path.basename(path)
    filesize = os.path.getsize(path)
    header = json.dumps({'name':filename, 'size':filesize}).encode('utf-8')

    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as sock:
        sock.connect((host, port))

        sock.sendall(struct.pack('>I', len(header)))

        sock.sendall(header)

        sent = 0
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                sock.sendall(chunk)
                sent += len(chunk)
                print(f"\rSent {sent}/{filesize} bytes", end='', flush=True)

    print(f"\nFile '{filename}' sent, {filesize} bytes")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Using python3 '{sys.argv[0]}'")
        sys.exit(1)
    print(f"Sending file '{sys.argv[1]}'")
    send_file(sys.argv[1])