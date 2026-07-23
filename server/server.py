import argparse
import socket


def build_parser():
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    return parser


def main():
    args = build_parser().parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen(1)
        print(f"Server listening on {args.host}:{args.port}")

        conn, addr = server_sock.accept()
        with conn:
            print(f"Connection from {addr}")


if __name__ == "__main__":
    main()