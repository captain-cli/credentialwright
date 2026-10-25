import tempfile
import unittest
from pathlib import Path
from credentialwright.cli import main
from credentialwright.core import ensure
SPEC = {"credentials":{"API_KEY":{"bytes":32}}}
class CheckTest(unittest.TestCase):
    def test_check_before_and_after_ensure(self):
        with tempfile.TemporaryDirectory() as t:
            import json
            spec=Path(t)/"spec.json"; spec.write_text(json.dumps(SPEC))
            out=Path(t)/"private.env"
            self.assertEqual(main(["check","--spec",str(spec),"--output",str(out)]),2)
            ensure(SPEC,out)
            self.assertEqual(main(["check","--spec",str(spec),"--output",str(out)]),0)
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/"link.env"; target=Path(t)/"real.env";target.write_text("API_KEY=abc\n");path.symlink_to(target)
            with self.assertRaisesRegex(ValueError,"symlink"):
                ensure(SPEC,path)
