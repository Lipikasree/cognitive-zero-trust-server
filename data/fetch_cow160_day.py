"""Range-download one Cowrie event-log member from the CC BY 4.0 COW160 archive."""
from __future__ import annotations

import argparse
import shutil
import urllib.request
import zipfile
from pathlib import Path


RECORD_API = "https://zenodo.org/api/records/21260400"
CHUNK_BYTES = 8 * 1024 * 1024


class HttpRangeReader:
    def __init__(self, url: str, size: int):
        self.url, self.size, self.position = url, size, 0
        self.cache_start, self.cache = -1, b""

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0) -> int:
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        return self.position

    def tell(self) -> int:
        return self.position

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = self.size - self.position
        amount = min(amount, max(0, self.size - self.position))
        result = bytearray()
        while amount:
            if not (self.cache_start <= self.position < self.cache_start + len(self.cache)):
                self.cache_start = (self.position // CHUNK_BYTES) * CHUNK_BYTES
                end = min(self.size, self.cache_start + CHUNK_BYTES) - 1
                request = urllib.request.Request(self.url, headers={"Range": f"bytes={self.cache_start}-{end}"})
                with urllib.request.urlopen(request, timeout=90) as response:
                    if response.status != 206:
                        raise RuntimeError("Zenodo did not honor byte-range requests; refusing a full archive download")
                    self.cache = response.read()
                    content_range = response.headers.get("Content-Range", "")
                    if not content_range.startswith(f"bytes {self.cache_start}-"):
                        raise RuntimeError(f"Unexpected Content-Range response: {content_range}")
            offset = self.position - self.cache_start
            take = min(amount, len(self.cache) - offset)
            if take <= 0:
                break
            result.extend(self.cache[offset:offset + take])
            self.position += take
            amount -= take
        return bytes(result)


def fetch(day: str, output: Path) -> Path:
    record = urllib.request.urlopen(RECORD_API, timeout=30).read()
    import json
    metadata = json.loads(record)
    license_id = metadata.get("metadata", {}).get("license", {}).get("id")
    if license_id != "cc-by-4.0":
        raise RuntimeError(f"Expected CC BY 4.0 source terms; record reports {license_id!r}")
    archive = next(item for item in metadata["files"] if item["key"] == "data_all.zip")
    url = archive["links"]["self"]
    size = archive["size"]
    member_suffix = f"logs_by_day/{day}.json.gz"
    reader = HttpRangeReader(url, size)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(reader) as zf:
        candidates = [info for info in zf.infolist() if info.filename.lstrip("./") == member_suffix]
        if not candidates:
            raise ValueError(f"No {member_suffix} entry in the archive")
        with zf.open(candidates[0]) as source, output.open("wb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", default="2025-06-27", help="UTC date of one archive member (YYYY-MM-DD)")
    parser.add_argument("--output", type=Path, default=Path("data/external_raw/cowrie/cow160_day.json.gz"))
    args = parser.parse_args()
    path = fetch(args.day, args.output)
    print(f"Downloaded one Cowrie daily event log to {path}")


if __name__ == "__main__":
    main()
