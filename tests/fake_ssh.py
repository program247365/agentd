#!/usr/bin/env python3
"""Stands in for `ssh -N -L 127.0.0.1:L:127.0.0.1:R target` in tests: forwards
local port L to R. A target starting with "denied" fails like real ssh does."""
import socket, sys, threading

args = sys.argv[1:]
if args[-1].startswith("denied"):
    sys.stderr.write(f"{args[-1]}: Permission denied (publickey).\n")
    sys.exit(255)
_, lport, _, rport = args[args.index("-L") + 1].split(":")

def pipe(a, b):
    try:
        while (data := a.recv(65536)):
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(lport)))
srv.listen(16)
while True:
    client, _ = srv.accept()
    upstream = socket.create_connection(("127.0.0.1", int(rport)))
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
