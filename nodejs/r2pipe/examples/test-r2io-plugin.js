/*
 * Map this 4 MiB device with:
 * on "r2pipe://node test-r2io-plugin.js" 0x3c000000 rw 0x400000
 * See mapped-io.md for the complete firmware and Python examples.
 */

'use strict';

const r2pipe = require('../');
const SIZE = 4 * 1024 * 1024;
const memory = Buffer.alloc(SIZE);
memory.set([1, 2, 3]);

r2pipe.ioplugin((io, msg) => {
  // Addresses are offsets within the backend, not virtual addresses.
  // Normalize either legacy numbers or hexadecimal uint64 strings.
  let address;
  if (msg.op === 'read' || msg.op === 'write') {
    try {
      address = r2pipe.parseAddress(msg.address);
    } catch (error) {
      io.send({ result: -1, data: [] });
      return;
    }
  }
  // Convert to a Buffer index only after checking its bounded range.
  const valid = address !== undefined && address <= BigInt(SIZE);
  const offset = valid ? Number(address) : 0;
  switch (msg.op) {
    case 'read': {
      if (!valid || !Number.isSafeInteger(msg.count) || msg.count < 0) {
        io.send({ result: -1, data: [] });
        return;
      }
      const data = memory.subarray(offset, offset + Math.min(msg.count, SIZE - offset));
      io.send({ result: data.length, data: Array.from(data) });
      break;
    }
    case 'write': {
      if (!valid || !Array.isArray(msg.data) ||
          !msg.data.every(x => Number.isInteger(x) && x >= 0 && x <= 255)) {
        io.send({ result: -1 });
        return;
      }
      const count = Math.min(msg.data.length, SIZE - offset);
      memory.set(msg.data.slice(0, count), offset);
      io.send({ result: count });
      break;
    }
    case 'system':
      io.send({ result: '4 MiB in-memory device' });
      break;
    default:
      io.send({ result: -1 });
  }
});
