"""TCP client for sending a file to a remote server.

Implements a minimal length-prefixed transfer protocol. Since TCP is a
byte stream with no inherent message boundaries, the receiver cannot tell
where the file ends; the client therefore declares the payload size up
front, before sending any file data.

Wire format:
    [4 bytes]      header length, unsigned 32-bit big-endian integer
    [N bytes]      UTF-8 JSON header: {"name": str, "size": int}
    [size bytes]   raw file contents

The file is streamed in fixed-size chunks so that memory usage stays
constant regardless of the file size.

Usage:
    python client.py <file_path>
"""

import socket
import sys
import os
import json
import struct

HOST = 'localhost'
PORT = 9000
CHUNK = 65536

def send_file(path, host = HOST, port = PORT):
    """Send a single file to the server over a TCP connection.

        Opens a connection, transmits the length-prefixed JSON header
        describing the file, then streams the file contents in chunks of
        CHUNK bytes. Progress is printed to stdout as the transfer advances.
        The connection is closed automatically when the transfer completes.

        Only the base name of the file is sent, never the full path, so the
        local directory layout is not disclosed to the receiver.

        Args:
            path: Path to the file to send. Must be readable.
            host: Hostname or IP address of the receiving server.
            port: TCP port the server is listening on.

        Raises:
            FileNotFoundError: If path does not exist.
            OSError: If the connection cannot be established or the transfer
                is interrupted.
        """

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