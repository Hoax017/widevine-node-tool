#!/usr/bin/env node
'use strict';

// Sends a Widevine license request for a given PSSH and prints kid:key pairs,
// so the output can be diffed against the same PSSH run through the
// reference implementation (pywidevine / the browser extension).
//
// Usage:
//   node cli.js \
//     --wvd device.wvd \
//     --pssh <base64 pssh box OR raw init data> \
//     --url https://license.example.com/widevine \
//     [--header "Authorization: Bearer xxx"] [--header "X-Custom: y"] \
//     [--license-type STREAMING|OFFLINE|AUTOMATIC]
//     [--cache widevine-cache.json] [--refresh] [--no-cache]
//
// Results are cached in a JSON file (default ./widevine-cache.json), keyed on
// PSSH init data + license URL (without query string) + license type. A cache
// hit prints the stored keys without contacting the license server.
// --refresh forces a new request and overwrites the entry; --no-cache
// disables both reading and writing.
//
// Device credentials can also be passed as separate provisioned files:
//   --client-id client_id.bin --private-key private_key.pem

const { Cdm } = require('./widevine');
const device = require('./device');
const { toInitData } = require('./pssh');
const debug = require('./debug');
const cache = require('./cache');

function isProbablyText(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 64));
  if (!sample.length) return false;

  let printable = 0;
  for (const byte of sample) {
    if (byte === 0x09 || byte === 0x0A || byte === 0x0D || (byte >= 0x20 && byte <= 0x7E)) {
      printable += 1;
    }
  }

  return printable / sample.length >= 0.85;
}

function previewBuffer(buffer, limit = 48) {
  const sample = buffer.subarray(0, Math.min(buffer.length, limit));
  return {
    hex: sample.toString('hex'),
    ascii: sample.toString('utf8').replace(/[^\x20-\x7E]/g, '.'),
  };
}

function decodeBase64Payload(text) {
  const trimmed = text.trim();
  if (!trimmed) return null;

  const normalized = trimmed.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (normalized.length < 8 || normalized.length % 4 === 1 || !/^[A-Za-z0-9+/=]+$/.test(normalized)) {
    return null;
  }

  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const decoded = Buffer.from(padded, 'base64');
  if (!decoded.length) return null;

  return decoded;
}

function addCandidate(candidates, seen, label, bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (!buffer.length) return;

  const fingerprint = buffer.toString('base64');
  if (seen.has(fingerprint)) return;

  seen.add(fingerprint);
  candidates.push({ label, bytes: buffer });
}

function collectJsonStringLeaves(value, path = 'root', out = []) {
  if (typeof value === 'string') {
    out.push({ path, value });
    return out;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => collectJsonStringLeaves(item, `${path}[${index}]`, out));
    return out;
  }

  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      collectJsonStringLeaves(child, `${path}.${key}`, out);
    }
  }

  return out;
}

function extractLicenseResponseCandidates(rawBytes, contentType = '') {
  const candidates = [];
  const seen = new Set();
  addCandidate(candidates, seen, 'raw response body', rawBytes);

  const lowerContentType = String(contentType || '').toLowerCase();
  const text = rawBytes.toString('utf8').trim();
  const treatAsText = text.length > 0 && (
    lowerContentType.includes('json') ||
    lowerContentType.startsWith('text/') ||
    isProbablyText(rawBytes)
  );

  if (!treatAsText) return candidates;

  const inlineBase64 = decodeBase64Payload(text);
  if (inlineBase64) {
    addCandidate(candidates, seen, 'base64 response body', inlineBase64);
  }

  try {
    const parsed = JSON.parse(text);

    if (typeof parsed === 'string') {
      const decoded = decodeBase64Payload(parsed);
      if (decoded) {
        addCandidate(candidates, seen, 'JSON string payload', decoded);
      }
    }

    for (const leaf of collectJsonStringLeaves(parsed)) {
      const decoded = decodeBase64Payload(leaf.value);
      if (decoded) {
        addCandidate(candidates, seen, `JSON field ${leaf.path}`, decoded);
      }
    }
  } catch {
    // Not JSON.
  }

  if (text.includes('=')) {
    const params = new URLSearchParams(text);
    for (const [key, value] of params.entries()) {
      const decoded = decodeBase64Payload(value);
      if (decoded) {
        addCandidate(candidates, seen, `form field ${key}`, decoded);
      }
    }
  }

  return candidates;
}

async function parseLicenseResponse(cdm, sessionId, rawBytes, responseHeaders = {}) {
  const contentType = responseHeaders['content-type'] || '';
  const candidates = extractLicenseResponseCandidates(rawBytes, contentType);
  const failures = [];

  for (const candidate of candidates) {
    try {
      return await cdm.parseLicense(sessionId, candidate.bytes);
    } catch (err) {
      failures.push(`- ${candidate.label}: ${err.message}`);
    }
  }

  const preview = previewBuffer(rawBytes);
  const diagnostic = [
    'Unable to decode the license server response as a Widevine LICENSE SignedMessage.',
    `HTTP content-type: ${contentType || '<missing>'}`,
    `Body length: ${rawBytes.length} bytes`,
    `Body preview (hex): ${preview.hex || '<empty>'}`,
    `Body preview (ascii): ${preview.ascii || '<empty>'}`,
  ];

  if (failures.length) {
    diagnostic.push('Decode attempts:');
    diagnostic.push(...failures);
  }

  throw new Error(diagnostic.join('\n'));
}

function parseArgs(argv) {
  const args = { headers: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--debug') {
      args.debug = true;
    } else if (a === '--no-cache') {
      args.noCache = true;
    } else if (a === '--refresh') {
      args.refresh = true;
    } else if (a === '--header') {
      args.headers.push(argv[++i]);
    } else if (a.startsWith('--')) {
      args[a.slice(2)] = argv[++i];
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.debug) debug.enable();
  debug.log('parsed args:', { ...args, headers: args.headers });

  if (!args.pssh) {
    console.error('Missing --pssh (base64 pssh box, or raw init data)');
    process.exit(1);
  }
  if (!args.url) {
    console.error('Missing --url (license server endpoint)');
    process.exit(1);
  }

  const initData = toInitData(args.pssh);
  debug.log('PSSH init data: %d bytes, hex=%s', initData.length, Buffer.from(initData).toString('hex'));

  const licenseType = args['license-type'] || 'STREAMING';

  const useCache = !args.noCache;
  const cacheFile = args.cache || cache.DEFAULT_CACHE_FILE;
  const cacheKey = cache.computeCacheKey({ initData, url: args.url, licenseType });
  debug.log('cache: %s file=%s key=%s', useCache ? 'enabled' : 'disabled', cacheFile, cacheKey);

  if (useCache && !args.refresh) {
    const hit = cache.getEntry(cacheFile, cacheKey);
    if (hit) {
      debug.log('cache hit (stored %s)', hit.createdAt);
      for (const k of hit.keys) {
        console.log(`${k.kid}:${k.key}`);
      }
      console.error(`(from cache ${cacheFile}, stored ${hit.createdAt}; use --refresh to re-request)`);
      return;
    }
    debug.log('cache miss');
  }

  debug.log('loading device credentials...');
  const dev = args.wvd
    ? device.loadFromWvd(args.wvd)
    : device.loadFromParts(args['client-id'], args['private-key']);
  debug.log('device loaded: type=%d securityLevel=%d', dev.type, dev.securityLevel);
  debug.log('clientId size: %d bytes', dev.clientIdBytes.length);

  const cdm = new Cdm(dev);
  const sessionId = await cdm.open();
  debug.log('CDM session opened: %s', sessionId.toString('hex'));

  debug.log('requesting license challenge (type=%s)...', licenseType);
  const { challenge, requestId } = await cdm.getLicenseChallenge(
    sessionId,
    initData,
    licenseType,
  );
  debug.log('challenge generated: %d bytes, requestId=%s', challenge.length, requestId.toString('hex'));

  const headers = { 'Content-Type': 'application/octet-stream' };
  for (const h of args.headers) {
    const idx = h.indexOf(':');
    if (idx === -1) continue;
    const name = h.slice(0, idx).trim();
    const value = h.slice(idx + 1).trim();
    debug.log('header [%s]: %d chars', name, value.length);
    for (let ci = 0; ci < value.length; ci++) {
      if (value.charCodeAt(ci) > 255) {
        debug.log('  WARNING: non-Latin1 char at index %d: U+%s (%s)', ci, value.charCodeAt(ci).toString(16).toUpperCase(), value[ci]);
      }
    }
    headers[name] = value;
  }
  debug.log('POST %s (%d bytes)', args.url, challenge.length);

  let res;
  try {
    res = await fetch(args.url, {
      method: 'POST',
      headers,
      body: challenge,
    });
  } catch (err) {
    if (err.message.includes('ByteString')) {
      debug.log('ByteString error — dumping all header values:');
      for (const [k, v] of Object.entries(headers)) {
        debug.log('  %s: %d chars, non-ASCII positions: %s', k, v.length,
          [...v].map((c, i) => c.charCodeAt(0) > 255 ? `${i}=U+${c.charCodeAt(0).toString(16)}` : null).filter(Boolean).join(', ') || 'none');
      }
    }
    throw err;
  }
  debug.log('HTTP response: %d %s', res.status, res.statusText);

  if (!res.ok) {
    console.error(`License server returned HTTP ${res.status}`);
    console.error(await res.text());
    process.exit(1);
  }

  const responseHeaders = Object.fromEntries(res.headers.entries());
  debug.log('response headers:', responseHeaders);
  const licenseResponseBytes = Buffer.from(await res.arrayBuffer());
  debug.log('response body: %d bytes', licenseResponseBytes.length);

  const { keys, signatureOk } = await parseLicenseResponse(cdm, sessionId, licenseResponseBytes, responseHeaders);
  debug.log('keys extracted: %d total', keys.length);
  for (const k of keys) {
    debug.log('  key type=%s kid=%s key=%s', k.type, k.kid, k.key);
  }

  const contentKeys = keys
    .filter((k) => k.type === 'CONTENT')
    .map((k) => ({ kid: k.kid, key: k.key }));

  for (const k of contentKeys) {
    console.log(`${k.kid}:${k.key}`);
  }

  console.error(`(license server signature valid: ${signatureOk})`);

  if (useCache && contentKeys.length) {
    try {
      cache.setEntry(cacheFile, cacheKey, {
        createdAt: new Date().toISOString(),
        url: cache.normalizeUrl(args.url),
        licenseType,
        pssh: args.pssh,
        signatureOk,
        keys: contentKeys,
      });
      debug.log('cache: stored %d key(s) in %s', contentKeys.length, cacheFile);
    } catch (err) {
      console.error(`(warning: cannot write cache ${cacheFile}: ${err.message})`);
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.stack || err);
    process.exit(1);
  });
}

module.exports = {
  parseArgs,
  decodeBase64Payload,
  extractLicenseResponseCandidates,
  parseLicenseResponse,
};
