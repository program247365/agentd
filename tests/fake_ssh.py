#!/usr/bin/env python3
"""Stands in for ssh in tests. `ssh -N -L 127.0.0.1:L:127.0.0.1:R target`
forwards local port L to R; `ssh target command` runs the command with HOME
set to $FAKE_SSH_HOME (the "server's" home). A target starting with "denied"
fails like real ssh does."""
import os, socket, subprocess, sys, threading

args = sys.argv[1:]
if "-L" not in args:
    target, command = args[-2], args[-1]
    if target.startswith("denied"):
        sys.stderr.write(f"{target}: Permission denied (publickey).\n")
        sys.exit(255)
    env = dict(os.environ, HOME=os.environ["FAKE_SSH_HOME"])
    sys.exit(subprocess.run(["/bin/sh", "-c", command], env=env).returncode)
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
