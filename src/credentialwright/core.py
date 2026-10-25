"""Secret generation with preservation, explicit rotation and atomic private writes."""
import json
import os
import re
import secrets
import tempfile
from pathlib import Path

KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")

def parse_env(path):
    if path.is_symlink():
        raise ValueError("Refusing to read credentials from a symlink")
    if not path.exists():
        return {}
    if path.stat().st_mode & 0o077:
        raise ValueError("Credentials file permissions must be 0600 or stricter")
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Invalid .env entry")
        key, value = line.split("=", 1)
        key = key.strip()
        if not KEY.fullmatch(key) or key in result:
            raise ValueError("Invalid or duplicate credential key")
        result[key] = value.strip().strip('"')
    return result

def plan(spec, path, rotate=()):
    if not isinstance(spec, dict) or not isinstance(spec.get("credentials"), dict):
        raise ValueError("Spec requires 'credentials' object")
    current = parse_env(Path(path))
    rotate = set(rotate)
    if rotate - spec["credentials"].keys():
        raise ValueError("Cannot rotate unknown credential key")
    actions = {}
    for name, config in spec["credentials"].items():
        if not KEY.fullmatch(name):
            raise ValueError("Invalid credential name")
        nbytes = config.get("bytes", 32)
        if not isinstance(nbytes, int) or nbytes < 16 or nbytes > 4096:
            raise ValueError("Credential bytes must be an integer between 16 and 4096")
        actions[name] = "rotate" if name in rotate else "keep" if name in current else "create"
    return actions, current

def ensure(spec, path, dry_run=False, rotate=()):
    path = Path(path)
    actions, current = plan(spec, path, rotate)
    if dry_run:
        return actions
    if path.is_symlink():
        raise ValueError("Refusing to write credentials to a symlink")
    result = dict(current)
    for name, action in actions.items():
        if action != "keep":
            result[name] = secrets.token_hex(spec["credentials"][name].get("bytes", 32))
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never change existing credentials unless creating new keys or explicitly rotating.
    if all(action == "keep" for action in actions.values()) and path.exists():
        return actions
    fd, temp = tempfile.mkstemp(prefix=".credentials-", dir=path.parent)
    try:
        os.chmod(temp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for name in sorted(result):
                f.write(f"{name}={result[name]}\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return actions
