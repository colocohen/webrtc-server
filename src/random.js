// Random bytes from cryptographic-primitives, as a Buffer (the callers read
// them with Buffer's methods: readUInt32BE, toString('hex' / 'base64')) —
// a view of the library's array, not a copy.
import { random_bytes_sync } from 'cryptographic-primitives/random.js';

function randomBuffer(n) {
  var b = random_bytes_sync(n);
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
}

export { randomBuffer };
