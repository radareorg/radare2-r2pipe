# Mapping a virtual IO device

This example creates a 4 MiB in-memory device through the Node `r2pipe.ioplugin`
API, alongside the two SRAM regions from issue #148. The Python driver uses the
regular Python r2pipe client to configure and verify the maps.

Use a radare2 build with the r2pipe IO descriptor-offset and JSON-reply fixes,
and the Node helper from this checkout with the IO stream-framing fix. Older
builds can send virtual addresses to the device, truncate reads at 1024 bytes,
misreport successful writes, or lose protocol synchronization. These fixes are
required for the complete example; changing map permissions will not fix them.

## Run

Requirements: Linux/macOS, Node.js and radare2 in PATH, and Python 3 with r2pipe.
The backend loads the Node module directly from this checkout, so no npm install
is needed.

From the repository root:

```sh
python3 -m pip install ./python
cd nodejs/r2pipe/examples
python3 mapped-io.py
# Or supply your firmware:
python3 mapped-io.py /path/to/bios.hex
```

Without a firmware argument the script uses a synthetic 2 MiB BIOS buffer. It
checks that the device has exactly one map, reads its initial bytes, writes and
reads back `deadbeef`, verifies the last mapped byte, and reads 2048 bytes in one
request. The bulk fixture uses small `wx` commands to stay within the console's
command-length limit. The example always closes its r2 process in `finally`.

## Equivalent interactive command

From the same examples directory:

```sh
r2 -N -a arm -b 32 -e cfg.bigendian=true -e io.va=true \
  -c 'e asm.emu=true' \
  -c 'on malloc://16K 0x10000000 rwx' \
  -c 'omn 0x10000000 sram_1' \
  -c 'on malloc://128M 0x20000000 rwx' \
  -c 'omn 0x20000000 sram_2' \
  -c 'on "r2pipe://node test-r2io-plugin.js" 0x3c000000 rw 0x400000' \
  -c 'omn 0x3c000000 virtual_io' \
  bios.hex
```

Replace `bios.hex` with `malloc://2M` for a self-contained demonstration. Inside r2:

```text
om
pxj 4 @ 0x3c000000
wx deadbeef @ 0x3c000010
pxj 4 @ 0x3c000010
```

The reads return `[1,2,3,0]` and `[222,173,190,239]`. The additional maps are:

| Region | Start | Last byte | Permissions |
| --- | --- | --- | --- |
| sram_1 | 0x10000000 | 0x10003fff | rwx |
| sram_2 | 0x20000000 | 0x27ffffff | rwx |
| virtual_io | 0x3c000000 | 0x3c3fffff | rw- |

## Why the size matters

The syntax is `on <uri> <virtual-address> <permissions> <virtual-size>`. The
`0x400000` argument bounds the device map to 4 MiB. The r2pipe IO transport has no
size negotiation and otherwise reports an effectively unbounded descriptor;
automatically mapping that at a nonzero address wraps around the address space
and produces the two maps shown in issue #148. Allocating a JavaScript buffer
does not tell radare2 its size.

The backend receives **file-relative offsets**: virtual `0x3c000010` becomes
`"address": "0x10"` because this map has a zero physical offset. Its read handler must
return the actual byte count and that many bytes; its write handler returns the
number of bytes written. The implementation validates bounds and keeps data only
in memory until the process exits. Change its `SIZE` and the map-size argument
together to model a different device. Replace the buffer operations with device
accesses to adapt the example to hardware.

## Exact 64-bit addresses

Read and write requests now encode the offset as a hexadecimal string, for
example `{"op":"read","address":"0xffffffffffffffff","count":1}`. Backends
must also accept legacy numeric addresses. `r2pipe.parseAddress(msg.address)`
returns a `bigint` in Node/TypeScript; `r2pipe.parse_address(msg["address"])`
returns an `int` in Python. Both validate the unsigned 64-bit range.

Only convert a JavaScript address to `Number` after checking it fits your buffer
(or `Number.MAX_SAFE_INTEGER`). Already-unsafe JavaScript numbers are rejected;
their lost bits cannot be recovered. TypeScript's `parseJson` preserves legacy
large integer literals as `bigint`, which `parseAddress` also accepts. Other JSON
strings are left unchanged.

A Python implementation is included at `python/examples/io-plugin.py`. From this
examples directory, run the same checks with:

```sh
python3 mapped-io.py --python-backend
```
