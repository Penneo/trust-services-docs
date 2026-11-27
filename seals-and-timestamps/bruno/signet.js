const crypto = require('crypto');
const fs = require('fs');

const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;
const PS256_SALT_LENGTH = 32;

const DER_INTEGER = 0x02;
const DER_OCTET_STRING = 0x04;
const DER_SEQUENCE = 0x30;
const DER_NULL = Buffer.from([0x05, 0x00]);
const SHA512_OID = Buffer.from('0609608648016503040203', 'hex');
const TIMESTAMP_REQUEST_VERSION = Buffer.from([0x02, 0x01, 0x01]);
const CERTIFICATE_REQUESTED = Buffer.from([0x01, 0x01, 0xff]);

function readClientKey(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const isJwk = content.trim().startsWith('{');
  if (isJwk) {
    const jwk = JSON.parse(content);
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  }
  return crypto.createPrivateKey(content);
}

function buildClientAssertion({ clientId, clientKey, keyId, tokenEndpoint }) {
  const now = readEpochSeconds();
  const header = { alg: 'PS256', typ: 'JWT', kid: keyId };
  const claims = {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + CLIENT_ASSERTION_LIFETIME_SECONDS,
  };
  const signingKey = {
    key: clientKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: PS256_SALT_LENGTH,
  };
  return signJwt(header, claims, signingKey);
}

function createDpopKey() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return privateKey.export({ format: 'jwk' });
}

function buildDpopProof({ dpopKey, method, url, accessToken }) {
  const { kty, crv, x, y } = dpopKey;
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty, crv, x, y } };
  const targetUri = url.split(/[?#]/)[0];
  const claims = { jti: crypto.randomUUID(), htm: method, htu: targetUri, iat: readEpochSeconds() };
  if (accessToken) {
    claims.ath = hashAccessToken(accessToken);
  }
  const privateKey = crypto.createPrivateKey({ key: dpopKey, format: 'jwk' });
  return signJwt(header, claims, { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

function buildTimestampRequest(hashToTimestamp) {
  const hash = Buffer.from(hashToTimestamp, 'base64');
  const sha512Algorithm = encodeDer(DER_SEQUENCE, Buffer.concat([SHA512_OID, DER_NULL]));
  const hashedMessage = encodeDer(DER_OCTET_STRING, hash);
  const messageImprint = encodeDer(DER_SEQUENCE, Buffer.concat([sha512Algorithm, hashedMessage]));
  const nonce = encodeDer(DER_INTEGER, createNonce());
  const fields = [TIMESTAMP_REQUEST_VERSION, messageImprint, nonce, CERTIFICATE_REQUESTED];
  return encodeDer(DER_SEQUENCE, Buffer.concat(fields));
}

function createNonce() {
  const nonce = crypto.randomBytes(8);
  nonce[0] = (nonce[0] & 0x7f) | 0x01;
  return nonce;
}

function encodeDer(tag, content) {
  const header = Buffer.from([tag, content.length]);
  return Buffer.concat([header, content]);
}

function hashAccessToken(accessToken) {
  return crypto.createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

function signJwt(header, claims, signingKey) {
  const encodedHeader = encodeSegment(header);
  const encodedClaims = encodeSegment(claims);
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), signingKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

function encodeSegment(object) {
  const json = JSON.stringify(object);
  return Buffer.from(json).toString('base64url');
}

function readEpochSeconds() {
  return Math.floor(Date.now() / 1000);
}

module.exports = { readClientKey, buildClientAssertion, createDpopKey, buildDpopProof, buildTimestampRequest };
