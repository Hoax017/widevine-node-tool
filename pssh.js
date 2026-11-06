'use strict';
const debug = require('./debug');

// Extracts the inner `data` payload from a (v0 or v1) ISO BMFF `pssh` box,
// mirroring what pywidevine's PSSH class exposes as `.init_data` (the bytes
// that go into LicenseRequest.content_id.widevine_pssh_data.pssh_data).
//
// Box layout (v0):
//   size(4) 'pssh'(4) version(1)+flags(3) system_id(16) data_size(4) data(data_size)
// Box layout (v1):
//   ...same... + kid_count(4) + kid_count * 16 bytes, then data_size(4) data(...)
function extractInitDataFromPsshBox(boxBytes) {
  if (boxBytes.length < 32) {
    throw new Error('Buffer too short to be a pssh box');
  }
  const type = boxBytes.toString('ascii', 4, 8);
  if (type !== 'pssh') {
    throw new Error(`Expected 'pssh' box, got '${type}'`);
  }

  const version = boxBytes[8];
  let offset = 12 + 16; // version+flags(4) + system_id(16)

  if (version > 0) {
    const kidCount = boxBytes.readUInt32BE(offset);
    offset += 4 + kidCount * 16;
  }

  const dataSize = boxBytes.readUInt32BE(offset);
  offset += 4;

  return boxBytes.subarray(offset, offset + dataSize);
}

// Accepts either a full pssh box, or raw init data already stripped of the
// box header (e.g. if you already extracted it elsewhere) — if it doesn't
// look like a 'pssh' box, it's returned as-is.
function toInitData(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'base64');
  debug.log('PSSH input: %d bytes', buf.length);
  if (buf.length >= 8 && buf.toString('ascii', 4, 8) === 'pssh') {
    debug.log('detected pssh box, extracting init data (version=%d)', buf[8]);
    const data = extractInitDataFromPsshBox(buf);
    debug.log('extracted init data: %d bytes', data.length);
    return data;
  }
  debug.log('treating input as raw init data');
  return buf;
}

module.exports = { extractInitDataFromPsshBox, toInitData };
