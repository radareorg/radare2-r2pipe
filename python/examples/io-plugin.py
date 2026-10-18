#!/usr/bin/env python3
"""4 MiB memory device: on \"r2pipe://python3 io-plugin.py\" 0x3c000000 rw 0x400000."""
import json
import sys
import r2pipe

memory = bytearray(4 * 1024 * 1024)
memory[:3] = b"\x01\x02\x03"


def handle(message):
    """Accept both legacy numeric addresses and hexadecimal uint64 strings."""
    if message["op"] == "system":
        return {"result": "4 MiB in-memory device"}
    try:
        offset = r2pipe.parse_address(message["address"])
    except (KeyError, TypeError, ValueError):
        return {"result": -1, "data": []}
    if offset > len(memory):
        return {"result": -1, "data": []}
    if message["op"] == "read":
        count = message["count"]
        if type(count) is not int or count < 0:
            return {"result": -1, "data": []}
        data = memory[offset:offset + min(count, len(memory) - offset)]
        return {"result": len(data), "data": list(data)}
    if message["op"] == "write":
        data = message["data"]
        if not isinstance(data, list) or any(type(x) is not int or not 0 <= x <= 255 for x in data):
            return {"result": -1}
        count = min(len(data), len(memory) - offset)
        memory[offset:offset + count] = bytes(data[:count])
        return {"result": count}
    return {"result": -1}


if __name__ == "__main__":
    sys.stdout.write("\0")
    sys.stdout.flush()
    for line in sys.stdin:
        response = handle(json.loads(line))
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\0")
        sys.stdout.flush()
