import hashlib, json, tempfile, unittest, zipfile
from pathlib import Path
from scripts import build_private_release_bridge_package as build
class Tests(unittest.TestCase):
 def test_package_is_deterministic_dormant_and_exact(self):
  with tempfile.TemporaryDirectory() as folder:
   first=Path(folder)/"a.zip"; second=Path(folder)/"b.zip"
   one=build.build(first); two=build.build(second)
   self.assertEqual(first.read_bytes(),second.read_bytes()); self.assertEqual(one["packageSha256"],hashlib.sha256(first.read_bytes()).hexdigest()); self.assertEqual(one,two)
   with zipfile.ZipFile(first) as archive:
    names=archive.namelist(); self.assertEqual(names,[build.JOB+item[1] for item in build.SOURCES]+[build.JOB+"private_release_bridge_members.json"])
    self.assertTrue(all(name.startswith(build.JOB) for name in names)); self.assertEqual(len(names),len(set(names)))
    manifest=json.loads(archive.read(build.JOB+"private_release_bridge_members.json"))
    for name,digest in manifest["members"].items(): self.assertEqual(hashlib.sha256(archive.read(build.JOB+name)).hexdigest(),digest)
 def test_existing_output_is_never_overwritten(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/"x.zip"; path.write_bytes(b"keep")
   with self.assertRaises(build.PackageError): build.build(path)
   self.assertEqual(path.read_bytes(),b"keep")
if __name__=="__main__": unittest.main()
