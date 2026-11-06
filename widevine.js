'use strict';
const crypto = require('crypto');
const protobuf = require('protobufjs');
const path = require('path');
const { cmac } = require('./cmac');
const debug = require('./debug');

const PROTO_PATH = path.join(__dirname, 'proto', 'license_protocol.proto');

let root;
async function loadProto() {
  if (!root) {
    root = await protobuf.load(PROTO_PATH);
  }
  return root;
}

// Mirrors pywidevine Cdm.derive_context() + Cdm.derive_keys() exactly
// (AES-128-CMAC based key derivation, RFC 4493 / NIST SP800-108-ish).
function deriveContext(licenseRequestBytes) {
  const encLabel = Buffer.from('ENCRYPTION\x00', 'binary');
  const encContext = Buffer.concat([
    encLabel,
    licenseRequestBytes,
    Buffer.from([0x00, 0x00, 0x00, 0x80]), // 128-bit key size, big-endian
  ]);

  const macLabel = Buffer.from('AUTHENTICATION\x00', 'binary');
  const macContext = Buffer.concat([
    macLabel,
    licenseRequestBytes,
    Buffer.from([0x00, 0x00, 0x02, 0x00]), // 512-bit key size, big-endian
  ]);

  return { encContext, macContext };
}

function deriveKeys(encContext, macContext, sessionKey) {
  const derive = (ctx, counter) => cmac(sessionKey, Buffer.concat([Buffer.from([counter]), ctx]));

  const encKey = derive(encContext, 1);
  const macKeyServer = Buffer.concat([derive(macContext, 1), derive(macContext, 2)]);
  const macKeyClient = Buffer.concat([derive(macContext, 3), derive(macContext, 4)]);

  return { encKey, macKeyServer, macKeyClient };
}

function previewBytes(bytes, limit = 48) {
  const sample = Buffer.from(bytes).subarray(0, Math.min(bytes.length, limit));
  return {
    hex: sample.toString('hex'),
    ascii: sample.toString('utf8').replace(/[^\x20-\x7E]/g, '.'),
  };
}

class Cdm {
  constructor(device) {
    this.device = device;
    this.sessions = new Map();
  }

  async open() {
    debug.log('loading protobuf schema...');
    await loadProto();
    const sessionId = crypto.randomBytes(16);
    this.sessions.set(sessionId.toString('hex'), { context: new Map() });
    debug.log('session created: %s', sessionId.toString('hex'));
    return sessionId;
  }

  async getLicenseChallenge(sessionId, psshInitData, licenseType = 'STREAMING') {
    const r = await loadProto();
    const session = this.sessions.get(sessionId.toString('hex'));
    if (!session) throw new Error('Invalid session');

    const LicenseRequest = r.lookupType('license_protocol.LicenseRequest');
    const SignedMessage = r.lookupType('license_protocol.SignedMessage');
    const LicenseTypeEnum = r.lookupEnum('license_protocol.LicenseType');
    const ProtocolVersionEnum = r.lookupEnum('license_protocol.ProtocolVersion');
    const RequestTypeEnum = r.lookupEnum('license_protocol.LicenseRequest.RequestType');
    const MessageTypeEnum = r.lookupEnum('license_protocol.SignedMessage.MessageType');

    const requestId = crypto.randomBytes(16);

    const licenseRequestMsg = LicenseRequest.create({
      clientId: this.device.clientIdBytes,
      contentId: {
        widevinePsshData: {
          psshData: [psshInitData],
          licenseType: LicenseTypeEnum.values[licenseType],
          requestId,
        },
      },
      type: RequestTypeEnum.values.NEW,
      requestTime: Math.floor(Date.now() / 1000),
      protocolVersion: ProtocolVersionEnum.values.VERSION_2_1,
      keyControlNonce: 1 + Math.floor(Math.random() * (2 ** 31 - 1)),
    });

    const licenseRequestBytes = LicenseRequest.encode(licenseRequestMsg).finish();
    debug.log('LicenseRequest encoded: %d bytes', licenseRequestBytes.length);

    const signature = crypto.sign('sha1', licenseRequestBytes, {
      key: this.device.privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });

    const signedMessageMsg = SignedMessage.create({
      type: MessageTypeEnum.values.LICENSE_REQUEST,
      msg: licenseRequestBytes,
      signature,
    });
    const signedMessageBytes = SignedMessage.encode(signedMessageMsg).finish();
    debug.log('SignedMessage (challenge) encoded: %d bytes', signedMessageBytes.length);
    debug.log('RSA-PSS signature: %d bytes', signature.length);

    session.context.set(requestId.toString('hex'), deriveContext(licenseRequestBytes));

    return { challenge: Buffer.from(signedMessageBytes), requestId };
  }

  async parseLicense(sessionId, licenseResponseBytes) {
    const r = await loadProto();
    const session = this.sessions.get(sessionId.toString('hex'));
    if (!session) throw new Error('Invalid session');

    const SignedMessage = r.lookupType('license_protocol.SignedMessage');
    const License = r.lookupType('license_protocol.License');

    const MessageTypeEnum = r.lookupEnum('license_protocol.SignedMessage.MessageType');
    debug.log('decoding license response (%d bytes)...', licenseResponseBytes.length);
    let signedMessage;
    try {
      signedMessage = SignedMessage.decode(licenseResponseBytes);
    } catch (err) {
      const preview = previewBytes(licenseResponseBytes);
      throw new Error(
        [
          `Failed to decode license response as protobuf SignedMessage: ${err.message}`,
          `Preview (hex): ${preview.hex || '<empty>'}`,
          `Preview (ascii): ${preview.ascii || '<empty>'}`,
        ].join('\n'),
        { cause: err },
      );
    }

    const typeName = MessageTypeEnum.valuesById[signedMessage.type] || signedMessage.type;
    debug.log('SignedMessage type: %s', typeName);

    if (signedMessage.type !== MessageTypeEnum.values.LICENSE) {
      const typeName = MessageTypeEnum.valuesById[signedMessage.type] || signedMessage.type;
      throw new Error(`Expected a LICENSE message, got type=${typeName}`);
    }

    const license = License.decode(signedMessage.msg);
    debug.log('License decoded: %d key containers', license.key ? license.key.length : 0);

    const requestId = license.id && license.id.requestId;
    if (!requestId) throw new Error('License response has no id.request_id to match a session context');
    debug.log('requestId from license: %s', Buffer.from(requestId).toString('hex'));

    const context = session.context.get(Buffer.from(requestId).toString('hex'));
    if (!context) throw new Error('No matching license request context for this response (wrong session, or already parsed)');

    debug.log('decrypting session key with RSA-OAEP...');
    const decryptedSessionKey = crypto.privateDecrypt(
      {
        key: this.device.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1',
      },
      signedMessage.sessionKey,
    );

    debug.log('session key decrypted: %d bytes', decryptedSessionKey.length);
    debug.log('deriving enc/mac keys...');
    const { encKey, macKeyServer } = deriveKeys(context.encContext, context.macContext, decryptedSessionKey);
    debug.log('encKey: %s', encKey.toString('hex'));
    debug.log('macKeyServer: %s', macKeyServer.toString('hex'));

    const oemcryptoCoreMessage = signedMessage.oemcryptoCoreMessage && signedMessage.oemcryptoCoreMessage.length
      ? Buffer.from(signedMessage.oemcryptoCoreMessage)
      : Buffer.alloc(0);
    const computedSignature = crypto
      .createHmac('sha256', macKeyServer)
      .update(oemcryptoCoreMessage)
      .update(signedMessage.msg)
      .digest();

    const signatureOk = Buffer.isBuffer(signedMessage.signature) &&
      crypto.timingSafeEqual(signedMessage.signature, computedSignature);
    debug.log('signature verification: %s', signatureOk ? 'OK' : 'FAILED');

    const KeyTypeEnum = r.lookupEnum('license_protocol.License.KeyContainer.KeyType');
    const keys = license.key.map((kc) => {
      debug.log('decrypting key container: type=%s iv=%s', KeyTypeEnum.valuesById[kc.type] || kc.type, Buffer.from(kc.iv).toString('hex'));
      const decipher = crypto.createDecipheriv('aes-128-cbc', encKey, kc.iv);
      const decrypted = Buffer.concat([decipher.update(kc.key), decipher.final()]);
      let kidHex = kc.id && kc.id.length ? Buffer.from(kc.id).toString('hex') : '';
      if (kidHex.length < 32) kidHex = kidHex.padEnd(32, '0');
      return {
        type: KeyTypeEnum.valuesById[kc.type] || String(kc.type),
        kid: kidHex,
        key: decrypted.toString('hex'),
      };
    });

    session.context.delete(Buffer.from(requestId).toString('hex'));

    return { keys, signatureOk };
  }
}

module.exports = { Cdm };
