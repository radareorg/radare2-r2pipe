"""Offline release/download behavior, including pagination and unsafe archives."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r2pipe_wasm.releases import API, DownloadManager, WASM_HEADER


def release(tag="6.2.2", *, api=True, prerelease=False):
    return {"tag_name": tag, "draft": False, "prerelease": prerelease,
            "assets": [{"id": 42, "name": f"radare2-{tag}-wasi-api.zip",
                        "browser_download_url": "https://github.com/asset"}] if api else []}


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as package:
        for name, data in entries:
            package.writestr(name, data)
    return buffer.getvalue()


class ReleasesTest(unittest.TestCase):
    def test_pagination_and_selection(self):
        manager = DownloadManager()
        first = [release("new", api=False)] * 98 + [release(prerelease=True),
                                                           dict(release(), draft=True)]
        with patch.object(manager, "_json", side_effect=[first, [release()]]) as request:
            self.assertEqual(manager.select()["tag_name"], "6.2.2")
            self.assertEqual(request.call_args.args[0], API + "?per_page=100&page=2")
        with patch.object(manager, "_json", return_value=[release(prerelease=True), release(api=False)]):
            self.assertEqual(len(list(manager.releases())), 2)
            with self.assertRaisesRegex(ValueError, "No stable"):
                manager.select()

    def test_network_variant(self):
        manager = DownloadManager()
        selected = release()
        with patch.object(manager, "_json", return_value=selected):
            with self.assertRaisesRegex(ValueError, "no wasi-api-net"):
                manager.select("6.2.2", network=True)
        selected["assets"][0]["name"] = "radare2-future-wasi-api-net.zip"
        with patch.object(manager, "_json", return_value=selected):
            self.assertEqual(manager.select("future", network=True), selected)
            with self.assertRaisesRegex(ValueError, "no wasi-api build"):
                manager.select("future")

    def test_exact_tag(self):
        manager = DownloadManager()
        with patch.object(manager, "_json", return_value=release(prerelease=True)) as request:
            manager.select("test/tag")
            self.assertTrue(request.call_args.args[0].endswith("/tags/test%2Ftag"))
        with patch.object(manager, "_json", return_value=release(api=False)):
            with self.assertRaisesRegex(ValueError, "no wasi-api"):
                manager.select("6.2.4")

    def test_cache_and_digest(self):
        data = archive([("../../radare2.wasm", WASM_HEADER + b"fixture")])
        selected = release()
        selected["assets"][0]["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            manager = DownloadManager(temporary)
            with patch.object(manager, "select", return_value=selected), patch.object(
                    manager, "_request", side_effect=lambda *_a, **_k: io.BytesIO(data)) as request:
                path = manager.download()
                self.assertEqual(path.read_bytes(), WASM_HEADER + b"fixture")
                self.assertEqual(manager.download(), path)
                self.assertEqual(request.call_count, 1)
                self.assertEqual(list(Path(temporary).rglob("*.wasm")), [path])
                selected["assets"][0]["digest"] = "sha256:incorrect"
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    manager.download(force=True)
                self.assertEqual(path.read_bytes(), WASM_HEADER + b"fixture")

    def test_bad_archives(self):
        cases = [([], "exactly one"),
                 ([("a/radare2.wasm", WASM_HEADER), ("b/radare2.wasm", WASM_HEADER)], "exactly one"),
                 ([("radare2.wasm", b"not wasm")], "WASM module")]
        with tempfile.TemporaryDirectory() as temporary:
            manager = DownloadManager(temporary)
            for entries, message in cases:
                with self.subTest(message=message), patch.object(manager, "select", return_value=release()), \
                        patch.object(manager, "_request", return_value=io.BytesIO(archive(entries))):
                    with self.assertRaisesRegex(ValueError, message):
                        manager.download()
            self.assertFalse(list(Path(temporary).rglob("*.wasm")))

    def test_token_only_on_api(self):
        manager = DownloadManager(token="secret")
        with patch("r2pipe_wasm.releases.urlopen") as request:
            manager._request(API, api=True)
            self.assertEqual(request.call_args.args[0].get_header("Authorization"), "Bearer secret")
            manager._request("https://github.com/asset")
            self.assertIsNone(request.call_args.args[0].get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
