"""Mock server for manually verifying client behaviour.

Accepts incoming connections and checks that the client speaks the
expected protocol, without writing anything to disk. Received file bytes
are counted and discarded, which makes this safe to run repeatedly and
suitable for large test files.

For each connection it reports whether:
    - the TCP connection was established
    - a valid length-prefixed JSON header was received
    - the number of bytes transferred matches the declared size

Any protocol violation is reported instead of raising, so a
misbehaving client does not take the server down.

Usage:
    python mock_server.py     # runs until interrupted with Ctrl+C
"""

import json
import socket
import struct

HOST = 'localhost'
PORT = 9000
CHUNK = 65536

def recv_exactly(sock, n):
    """Read exactly n bytes from a socket.

        A single recv() call may return fewer bytes than requested, since TCP
        delivers data in arbitrarily sized pieces. This loops until the
        requested amount has been accumulated, which is required when reading
        fixed-width fields such as the length prefix.

        Args:
            sock: A connected socket to read from.
            n: Exact number of bytes to read.

        Returns:
            A bytes object of exactly n bytes.

        Raises:
            ConnectionError: If the peer closes the connection before n bytes
                have been received.
        """

    data = bytearray()
    while len(data) < n:
        packet = sock.recv(min(CHUNK, n - len(data)))
        if not packet:
            raise ConnectionError("Connection closed earlier than expected")
        data.extend(packet)
    return bytes(data)


def check(conn, addr):
    """Validate one client connection and report the outcome.

        Reads the length prefix and JSON header, then consumes and discards
        the declared number of payload bytes, printing a status line for each
        stage. Protocol errors are caught and reported rather than
        propagated, so the server keeps accepting further connections.

        Args:
            conn: The accepted client socket.
            addr: The client address tuple, used for logging.
        """

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
    """Bind the listening socket and serve connections until interrupted.

        Handles one client at a time, sequentially. Ctrl+C shuts the server
        down cleanly.
        """

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