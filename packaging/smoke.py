#!/usr/bin/env python3
"""Smoke-tests a release tarball: unpacks it and runs the binary end to end
against the local store only, in a throwaway home. No network, no AWS.

    python3 -I packaging/smoke.py dist/kagebunshin-0.1.0-x86_64-unknown-linux-gnu.tar.gz 0.1.0

Passphrases are read from a terminal only, so the commands that ask for one
run on a pty here, answering each prompt in turn.
"""

import json
import os
import pty
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

PASSPHRASE = "smoke-test-passphrase"
VALUE = "kb-smoke-value"


def main(tarball, version):
    # Short: macOS caps a socket path at 104 bytes.
    root = tempfile.mkdtemp(prefix="kb-", dir="/tmp")
    daemon = None
    try:
        with tarfile.open(tarball) as t:
            t.extractall(root, filter="data")
        (top,) = [d for d in os.listdir(root)]
        kb = os.path.join(root, top, "kagebunshin")
        for f in ("LICENSE", "README.md"):
            assert os.path.isfile(os.path.join(root, top, f)), f"no {f} in the tarball"

        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.path.join(root, "home"),
            "XDG_CONFIG_HOME": os.path.join(root, "config"),
            "XDG_STATE_HOME": os.path.join(root, "state"),
            "KAGEBUNSHIN_SOCKET": os.path.join(root, "run", "kb.sock"),
        }
        for d in ("home", "config", "state", "run"):
            os.makedirs(os.path.join(root, d), mode=0o700)
        checkout = os.path.join(root, "widget")
        os.makedirs(checkout)

        def kb_run(*args, cwd=root, check=True):
            r = subprocess.run([kb, *args], cwd=cwd, env=env, capture_output=True, text=True)
            if check and r.returncode != 0:
                sys.exit(f"`kagebunshin {' '.join(args)}` exited {r.returncode}:\n{r.stdout}{r.stderr}")
            return r

        out = kb_run("--version").stdout.strip()
        assert out == f"kagebunshin {version}", f"--version said {out!r}"

        daemon = subprocess.Popen([kb, "daemon"], cwd=root, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 15
        while kb_run("daemon", "status", check=False).returncode != 0:
            if daemon.poll() is not None or time.monotonic() > deadline:
                sys.exit(f"the daemon did not come up:\n{daemon.stderr.read() if daemon.poll() is not None else ''}")
            time.sleep(0.2)

        # First: `store init` does not create the config directory itself.
        subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
        subprocess.run(["git", "remote", "add", "origin", "https://github.com/acme/widget.git"],
                       cwd=checkout, check=True)
        kb_run("project", "init", "widget", cwd=checkout)

        on_tty(kb, ["store", "init"], [PASSPHRASE, PASSPHRASE], root, env)
        on_tty(kb, ["store", "set", "widget.dev", "API_KEY"], [PASSPHRASE, VALUE], root, env)

        # The value reaches the child; nothing prints it.
        kb_run("run", "--", "sh", "-c", f'test "$API_KEY" = {VALUE}', cwd=checkout)
        r = kb_run("audit", "--json")
        assert VALUE not in r.stdout, "the audit log holds a value"
        events = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        assert events, "the audit log is empty"

        kb_run("lock")
        r = kb_run("run", "--", "true", cwd=checkout, check=False)
        assert r.returncode != 0, "run worked while locked"
        print(f"ok: {top}")
    finally:
        if daemon is not None:
            daemon.terminate()
            daemon.wait(timeout=10)
        shutil.rmtree(root, ignore_errors=True)


def on_tty(kb, args, answers, cwd, env):
    """Runs kagebunshin on a pty, answering each prompt (a line ending in
    ": ") with the next answer."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve(kb, [kb, *args], env)
    seen, log, answers = b"", b"", list(answers)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:  # Linux: EIO once the child is gone.
                break
            if not chunk:
                break
            seen += chunk
            log += chunk
            if answers and seen.rstrip(b" ").endswith(b":"):
                os.write(fd, answers.pop(0).encode() + b"\n")
                seen = b""
    else:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    code = os.waitstatus_to_exitcode(status)
    if code != 0 or answers:
        shown = log.decode(errors="replace").replace(PASSPHRASE, "<passphrase>")
        sys.exit(f"`kagebunshin {' '.join(args)}` exited {code}, {len(answers)} prompts unanswered:\n{shown}")


if __name__ == "__main__":
    main(*sys.argv[1:])
