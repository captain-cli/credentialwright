"""Adopt an owner-provisioned credential without rotating its database account.

Source and destination must be user-owned private regular files. Never print values.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat
import tempfile

_KEY = re.compile(r"[A-Z][A-Z0-9_]*\Z")


class AdoptionError(ValueError):
    """Safe user-facing errors without secret data."""


def _read_private(path: Path, *, allow_missing: bool = False) -> dict[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if allow_missing:
            return {}
        raise AdoptionError("Credential source file does not exist") from None
    except OSError:
        raise AdoptionError("Credential file could not be opened securely") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise AdoptionError("Credential file must be owned by the current user with 0600 or stricter permissions")
        with os.fdopen(fd, "r", encoding="utf-8") as file:
            fd = -1
            data: dict[str, str] = {}
            for raw in file:
                line = raw.rstrip("\r\n")
                if not line or line.lstrip().startswith("#"):
                    continue
                if "=" not in line:
                    raise AdoptionError("Invalid managed credential file")
                k, v = line.split("=", 1)
                if not _KEY.fullmatch(k) or k in data or not v or "\x00" in v:
                    raise AdoptionError("Invalid or duplicate managed credential")
                data[k] = v
            return data
    except UnicodeError:
        raise AdoptionError("Invalid credential encoding") from None
    finally:
        if fd >= 0:
            os.close(fd)


def adopt_credential(*, source: str | Path, output: str | Path, key: str, spec: dict,
                     dry_run: bool = False) -> str:
    """Return `import` or `keep` without exposing credential values.

    Refuse an existing differing value; no replacement/rotation is performed.
    `output` may already contain unrelated keys and they are preserved.
    """
    if not _KEY.fullmatch(key) or not isinstance(spec, dict) or not isinstance(spec.get("credentials"), dict) or key not in spec["credentials"]:
        raise AdoptionError("Credential key must be declared in the supplied spec")
    source = Path(source)
    output = Path(output)
    if source.absolute() == output.absolute():
        raise AdoptionError("Source and managed output must be different files")
    if source.is_symlink() or output.is_symlink():
        raise AdoptionError("Credential symlinks are not permitted")
    if not output.parent.is_dir():
        raise AdoptionError("Managed output directory must already exist")
    if not (output.parent.stat().st_mode & stat.S_IWUSR):
        raise AdoptionError("Managed output directory is not writable")

    # A dry run must not create even an advisory lock file.
    if dry_run:
        imported = _read_private(source)
        if key not in imported:
            raise AdoptionError("Declared key missing from source")
        existing = _read_private(output, allow_missing=True)
        if key in existing and existing[key] != imported[key]:
            raise AdoptionError("Managed credential differs from provisioned credential; refusing replacement")
        return "keep" if key in existing else "import"

    # Lock serializes adoption processes targeting the same destination.
    # Other writers must also honor this lock to guarantee global serialization.
    lock_path = output.with_name(output.name + ".adopt.lock")
    lock_fd = None
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.geteuid() or lock_stat.st_mode & 0o077:
            raise AdoptionError("Unsafe credential adoption lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        imported = _read_private(source)
        if key not in imported:
            raise AdoptionError("Declared key missing from source")
        existing = _read_private(output, allow_missing=True)
        if key in existing:
            if existing[key] != imported[key]:
                raise AdoptionError("Managed credential differs from provisioned credential; refusing replacement")
            return "keep"
        if dry_run:
            return "import"
        existing[key] = imported[key]
        mode = 0o600
        temp_path = None
        try:
            temp_fd, temp_name = tempfile.mkstemp(prefix=".credentialwright-adopt-", dir=output.parent)
            temp_path = Path(temp_name)
            os.fchmod(temp_fd, mode)
            with os.fdopen(temp_fd, "w", encoding="utf-8") as stream:
                for name in sorted(existing):
                    stream.write(f"{name}={existing[name]}\n")
                stream.flush()
                os.fsync(stream.fileno())
            # We only replace an existing file after rechecking that it was private.
            _read_private(output, allow_missing=True)
            os.replace(temp_path, output)
            temp_path = None
            # Best effort durability of parent directory metadata.
            dir_fd = os.open(output.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        return "import"
    except AdoptionError:
        raise
    except OSError:
        raise AdoptionError("Credential adoption failed; managed credential was not intentionally rotated") from None
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
