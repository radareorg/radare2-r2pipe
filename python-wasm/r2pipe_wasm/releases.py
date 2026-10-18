"""GitHub release discovery and downloads, executed by the Python host only."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile

API = "https://api.github.com/repos/radareorg/radare2/releases"
WASM_HEADER = b"\0asm\x01\0\0\0"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MODULE = 256 * 1024 * 1024


def api_asset(release):
    """Return the WASI reactor asset, or None (CLI/browser builds are unsuitable)."""
    return next((asset for asset in release.get("assets", [])
                 if asset["name"].startswith("radare2-")
                 and asset["name"].endswith("-wasi-api.zip")), None)


class DownloadManager:
    """List all public releases and cache their radare2.wasm API modules."""

    def __init__(self, cache_dir=None, *, token=None, timeout=60):
        self.cache_dir = Path(cache_dir) if cache_dir else Path(
            os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")
        ) / "r2pipe-wasm"
        self.token = token
        self.timeout = timeout

    def _request(self, url, *, api=False):
        headers = {"User-Agent": "r2pipe-wasm"}
        if api:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
        return urlopen(Request(url, headers=headers), timeout=self.timeout)

    def _json(self, url):
        with self._request(url, api=True) as response:
            return json.load(response)

    def releases(self):
        """Yield release dictionaries, including prereleases and non-WASM releases."""
        page = 1
        while True:
            entries = self._json(f"{API}?per_page=100&page={page}")
            for release in entries:
                if not release["draft"]:
                    yield release
            if len(entries) < 100:
                return
            page += 1

    def select(self, version="latest"):
        """Select the newest stable API build, or an exact GitHub tag."""
        if version != "latest":
            release = self._json(f"{API}/tags/{quote(version, safe='')}")
            if not api_asset(release):
                raise ValueError(f"Release {version} has no wasi-api build")
            return release
        for release in self.releases():
            if not release["prerelease"] and api_asset(release):
                return release
        raise ValueError("No stable radare2 release has a wasi-api build")

    def download(self, version="latest", *, force=False):
        """Return a cached Path; resolve the release via GitHub even on cache hits."""
        release = self.select(version)
        asset = api_asset(release)
        # Asset identity also distinguishes replacement assets and moving tags.
        identity = f"{asset['id']}:{asset.get('updated_at', '')}:{asset.get('digest', '')}"
        directory = self.cache_dir / hashlib.sha256(identity.encode()).hexdigest()
        destination = directory / "radare2.wasm"
        if not force and destination.is_file():
            with destination.open("rb") as cached:
                if cached.read(8) == WASM_HEADER:
                    return destination
        directory.mkdir(parents=True, exist_ok=True)
        # Only copy the selected member; never extract archive paths onto the host.
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            archive = Path(temporary) / "release.zip"
            digest = hashlib.sha256()
            size = 0
            with self._request(asset["browser_download_url"]) as response, archive.open("wb") as out:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_ARCHIVE:
                        raise ValueError("WASI archive exceeds 128 MiB")
                    digest.update(block)
                    out.write(block)
            expected = asset.get("digest")
            if expected and expected.startswith("sha256:"):
                if expected != "sha256:" + digest.hexdigest():
                    raise ValueError("WASI archive SHA-256 mismatch")
            with zipfile.ZipFile(archive) as package:
                entries = [entry for entry in package.infolist()
                           if PurePosixPath(entry.filename).name == "radare2.wasm"]
                if len(entries) != 1:
                    raise ValueError("Expected exactly one radare2.wasm in the API archive")
                if entries[0].file_size > MAX_MODULE:
                    raise ValueError("WASM module exceeds 256 MiB")
                module = package.read(entries[0])
            if not module.startswith(WASM_HEADER):
                raise ValueError("The release archive does not contain a WASM module")
            output = Path(temporary) / "radare2.wasm"
            output.write_bytes(module)
            os.replace(output, destination)
        return destination
