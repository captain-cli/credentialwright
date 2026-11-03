import os
import stat
import tempfile
import unittest
from pathlib import Path
from credentialwright.adopt import adopt_credential, AdoptionError

SPEC = {"credentials": {"APP_DB_PASSWORD": {"bytes": 32}, "JWT_SECRET": {"bytes": 64}}}


class AdoptTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.src = self.root / 'schemawright.env'
        self.dst = self.root / 'managed.env'
        self.src.write_text('APP_DB_PASSWORD=known-generated-token\n')
        self.src.chmod(0o600)

    def adopt(self, **kwargs):
        return adopt_credential(source=self.src, output=self.dst, key='APP_DB_PASSWORD', spec=SPEC, **kwargs)

    def test_import_and_idempotent(self):
        self.assertEqual(self.adopt(), 'import')
        self.assertEqual(self.dst.read_text(), self.src.read_text())
        self.assertEqual(stat.S_IMODE(self.dst.stat().st_mode), 0o600)
        self.assertEqual(self.adopt(), 'keep')

    def test_preserves_unrelated_existing_credentials(self):
        self.dst.write_text('JWT_SECRET=other\n')
        self.dst.chmod(0o600)
        self.assertEqual(self.adopt(), 'import')
        self.assertIn('JWT_SECRET=other\n', self.dst.read_text())
        self.assertIn('APP_DB_PASSWORD=known-generated-token\n', self.dst.read_text())

    def test_conflict_rejected_without_change(self):
        self.dst.write_text('APP_DB_PASSWORD=other\n')
        self.dst.chmod(0o600)
        with self.assertRaises(AdoptionError): self.adopt()
        self.assertEqual(self.dst.read_text(), 'APP_DB_PASSWORD=other\n')

    def test_dry_run_does_not_create_destination(self):
        self.assertEqual(self.adopt(dry_run=True), 'import')
        self.assertFalse(self.dst.exists())
        self.assertFalse(self.dst.with_name(self.dst.name + ".adopt.lock").exists())

    def test_rejects_insecure_source(self):
        self.src.chmod(0o644)
        with self.assertRaises(AdoptionError): self.adopt()

    def test_rejects_destination_symlink(self):
        self.dst.symlink_to(self.src)
        with self.assertRaises(AdoptionError): self.adopt()

    def test_rejects_undeclared_key(self):
        with self.assertRaises(AdoptionError):
            adopt_credential(source=self.src, output=self.dst, key='UNKNOWN', spec=SPEC)

    def test_rejects_duplicate_source_entries(self):
        self.src.write_text('APP_DB_PASSWORD=a\nAPP_DB_PASSWORD=b\n')
        with self.assertRaises(AdoptionError): self.adopt()

    def test_rejects_nonprivate_destination(self):
        self.dst.write_text('JWT_SECRET=a\n')
        self.dst.chmod(0o644)
        with self.assertRaises(AdoptionError): self.adopt()

if __name__ == '__main__':
    unittest.main()
