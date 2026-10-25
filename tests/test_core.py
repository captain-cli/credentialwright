import tempfile
import unittest
from pathlib import Path
from credentialwright.core import ensure, parse_env

SPEC = {"credentials": {"JWT_SECRET": {"bytes": 64}, "ARGON2_SALT": {"bytes": 16}}}

class SecretTests(unittest.TestCase):
    def test_idempotent_and_rotate(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)/"secrets.env"
            self.assertFalse(path.exists())
            self.assertEqual(ensure(SPEC, path, dry_run=True)["JWT_SECRET"], "create")
            self.assertFalse(path.exists())
            ensure(SPEC, path)
            first = parse_env(path)
            self.assertEqual(len(first["JWT_SECRET"]), 128)
            self.assertEqual(ensure(SPEC, path)["JWT_SECRET"], "keep")
            self.assertEqual(parse_env(path), first)
            ensure(SPEC, path, rotate=["JWT_SECRET"])
            current = parse_env(path)
            self.assertNotEqual(first["JWT_SECRET"], current["JWT_SECRET"])
            self.assertEqual(first["ARGON2_SALT"], current["ARGON2_SALT"])
    def test_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / ".env"
            p.write_text("JWT_SECRET=x\nJWT_SECRET=y\n")
            with self.assertRaises(ValueError):
                ensure(SPEC, p)

if __name__ == "__main__":
    unittest.main()
