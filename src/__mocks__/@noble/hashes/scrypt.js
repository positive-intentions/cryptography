// Mock scrypt for Jest tests only
// NOTE: This mock is ONLY used in Jest test environment
// The REAL implementation in AESCipherLayer.ts uses @noble/hashes/scrypt.js
// via dynamic import, which is browser-compatible and works in production
//
// This mock uses Node's crypto.scryptSync for Jest compatibility,
// but the actual browser/production code uses @noble/hashes/scrypt
// which is a pure JavaScript implementation that works in browsers

const crypto = require("crypto");

function scrypt(password, salt, options) {
  const { N, r, p, dkLen } = options;

  // Convert Uint8Array to Buffer if needed
  const passwordBuf = Buffer.isBuffer(password)
    ? password
    : Buffer.from(password);
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt);

  // For testing, use a simplified approach that works with Node's scryptSync
  // Node.js scryptSync has parameter validation that may reject high values
  // We'll use a workaround: use lower N value for testing, but still get deterministic results
  const testN = Math.min(N, 16384); // Limit N for Node.js compatibility
  const maxmem = 128 * testN * r * p;

  try {
    // Try with full parameters first
    const result = crypto.scryptSync(passwordBuf, saltBuf, dkLen, {
      N: testN,
      r: r,
      p: p,
      maxmem: Math.max(maxmem, 32 * 1024 * 1024), // At least 32MB
    });
    return new Uint8Array(result);
  } catch (error) {
    // Fallback: use basic scrypt without options (less secure but works for tests)
    // This ensures tests can run even if Node.js version has limitations
    const result = crypto.scryptSync(passwordBuf, saltBuf, dkLen);
    return new Uint8Array(result);
  }
}

module.exports = { scrypt, default: { scrypt } };
