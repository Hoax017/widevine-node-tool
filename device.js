'use strict';
const fs = require('fs');
const crypto = require('crypto');
const debug = require('./debug');

// Loads device credentials for a *properly provisioned* Widevine CDM.
// Two supported input forms:
//
// 1. `.wvd` container (pywidevine's own v2 format):
//      loadFromWvd(path)
//
// 2. Separate files as handed out by a Widevine partner portal:
//      loadFromParts(clientIdPath, privateKeyPemPath)
//    - clientIdPath: raw serialized ClientIdentification protobuf bytes
//      (often named client_id.bin / device_client_id_blob)
//    - privateKeyPemPath: RSA private key, PEM or DER

function derToPem(der) {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}

function importPrivateKey(keyBytes) {
  const asString = keyBytes.toString('utf8');
  if (asString.includes('-----BEGIN')) {
    return crypto.createPrivateKey(asString);
  }
  // Assume DER (PKCS#1 or PKCS#8) — try PKCS#8 first, fall back to PKCS#1.
  try {
    return crypto.createPrivateKey({ key: keyBytes, format: 'der', type: 'pkcs8' });
  } catch (e) {
    return crypto.createPrivateKey({ key: keyBytes, format: 'der', type: 'pkcs1' });
  }
}

// Parses the .wvd v2 struct:
//   'WVD'(3) version(1)=2 type(1) security_level(1) flags(1)
//   private_key_len(2 BE) private_key(N)
//   client_id_len(2 BE) client_id(M)
function loadFromWvd(path) {
  debug.log('reading WVD file: %s', path);
  const buf = fs.readFileSync(path);
  debug.log('WVD file size: %d bytes', buf.length);

  if (buf.toString('ascii', 0, 3) !== 'WVD') {
    throw new Error('Not a WVD file (missing magic)');
  }
  const version = buf[3];
  if (version !== 2) {
    throw new Error(`Unsupported WVD version ${version}, only v2 is supported by this tool`);
  }

  const type = buf[4]; // 1 = CHROME, 2 = ANDROID
  const securityLevel = buf[5];
  debug.log('WVD v%d type=%d securityLevel=%d', version, type, securityLevel);
  let offset = 7; // skip flags byte too

  const privateKeyLen = buf.readUInt16BE(offset);
  offset += 2;
  const privateKeyBytes = buf.subarray(offset, offset + privateKeyLen);
  offset += privateKeyLen;
  debug.log('private key: %d bytes', privateKeyLen);

  const clientIdLen = buf.readUInt16BE(offset);
  offset += 2;
  const clientIdBytes = buf.subarray(offset, offset + clientIdLen);
  debug.log('client ID: %d bytes', clientIdLen);

  return {
    type,
    securityLevel,
    privateKey: importPrivateKey(privateKeyBytes),
    clientIdBytes: Buffer.from(clientIdBytes),
  };
}

function loadFromParts(clientIdPath, privateKeyPemPath, { type = 2, securityLevel = 3 } = {}) {
  debug.log('loading client ID from: %s', clientIdPath);
  debug.log('loading private key from: %s', privateKeyPemPath);
  const clientIdBytes = fs.readFileSync(clientIdPath);
  const privateKeyBytes = fs.readFileSync(privateKeyPemPath);
  debug.log('client ID: %d bytes, private key: %d bytes', clientIdBytes.length, privateKeyBytes.length);
  return {
    type,
    securityLevel,
    privateKey: importPrivateKey(privateKeyBytes),
    clientIdBytes: Buffer.from(clientIdBytes),
  };
}

module.exports = { loadFromWvd, loadFromParts, derToPem };
