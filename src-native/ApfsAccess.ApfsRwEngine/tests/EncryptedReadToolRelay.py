"""Public negative: child inherits a pipe created by its grandparent."""
import subprocess, sys
raise SystemExit(subprocess.run(sys.argv[1:], stdin=sys.stdin.buffer,
    stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, timeout=5).returncode)
