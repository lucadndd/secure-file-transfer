import json
import socket
import struct

HOST = 'localhost'
PORT = 9000
CHUNK = 65536

def recv_exactly(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(min(CHUNK, n - len(data)))
        if not packet:
            raise ConnectionError("Connection closed earlier than expected")
        data.extend(packet)
    return bytes(data)


def check(conn, addr):
    print(f"[OK] TCP connection established by {addr}")
    try:
        header_len = struct.unpack(">I", recv_exactly(conn, 4))[0]
        header = json.loads(recv_exactly(conn, header_len).decode('utf-8'))
        print(f"[OK] header received: {header}")

        size = int(header['size'])
        received = 0
        while received < size:
            chunk = conn.recv(min(CHUNK, size - received))
            if not chunk:
                break
            received += len(chunk)

        if received == size:
            print(f"[OK] trasnfer completed: {received}/{size} bytes\n")
        else:
            print(f"[!!] transfer incompleted: {received}/{size} bytes\n")
    except (ConnectionError, ValueError, KeyError, struct.error) as e:
        print(f"[!!] the client did not respect the protocol: {e}\n")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen()
        print(f"[*] Mock server listening on {HOST}:{PORT}  (Ctrl+C to exit)\n")
        try:
            while True:
                conn, addr = sock.accept()
                with conn:
                    check(conn, addr)
        except KeyboardInterrupt:
            print("\n[*] Mock server stopped")


if __name__ == "__main__":
    main()