// Jest setup file for crypto functionality tests
import { TextEncoder, TextDecoder } from 'util';

// Provide TextEncoder and TextDecoder for Jest environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Provide basic File implementation for tests
global.File = class File {
  constructor(bits, filename, options = {}) {
    this.bits = bits;
    this.name = filename;
    this.type = options.type || '';
    this.size = bits.reduce((acc, bit) => acc + (bit.length || bit.byteLength || 0), 0);
  }
  
  async text() {
    return this.bits.join('');
  }
  
  async arrayBuffer() {
    const text = this.bits.join('');
    return new TextEncoder().encode(text).buffer;
  }
};

// Provide Blob implementation for tests
global.Blob = class Blob {
  constructor(bits, options = {}) {
    this.bits = bits;
    this.type = options.type || '';
  }
};

// Provide URL methods for file downloads
global.URL = {
  createObjectURL: jest.fn(() => 'blob:test-url'),
  revokeObjectURL: jest.fn()
};

// Provide document methods for file downloads
global.document = {
  createElement: jest.fn(() => ({
    href: '',
    download: '',
    click: jest.fn(),
    remove: jest.fn()
  })),
  body: {
    appendChild: jest.fn(),
    removeChild: jest.fn()
  }
};

// Mock crypto.subtle for tests
const mockSubtle = {
  digest: jest.fn(() => Promise.resolve(new ArrayBuffer(32))),
  generateKey: jest.fn((algorithm) => {
    if (algorithm.name === 'RSA-OAEP') {
      return Promise.resolve({ 
        publicKey: { type: 'public' }, 
        privateKey: { type: 'private' } 
      });
    } else if (algorithm.name === 'AES-GCM') {
      return Promise.resolve({ type: 'secret' });
    }
    return Promise.resolve({ type: 'unknown' });
  }),
  exportKey: jest.fn((format, key) => {
    if (format === 'jwk') {
      return Promise.resolve({
        kty: key.type === 'public' || key.type === 'private' ? 'RSA' : 'oct',
        use: 'enc',
        key_ops: key.type === 'public' ? ['encrypt'] : key.type === 'private' ? ['decrypt'] : ['encrypt', 'decrypt'],
        alg: 'RS256',
        n: 'test-n-value',
        e: 'AQAB'
      });
    }
    return Promise.resolve(new ArrayBuffer(256));
  }),
  importKey: jest.fn((format, keyData) => {
    // Handle raw key data (for PBKDF2 etc.)
    if (format === 'raw') {
      return Promise.resolve({ type: 'imported-raw' });
    }
    
    // Handle JWK format
    if (format === 'jwk') {
      if (typeof keyData === 'string') {
        keyData = JSON.parse(keyData);
      }
      if (!keyData.kty) {
        throw new Error('Invalid JWK format');
      }
    }
    
    return Promise.resolve({ type: 'imported' });
  }),
  deriveKey: jest.fn(() => Promise.resolve({ type: 'derived' })),
  encrypt: jest.fn(() => Promise.resolve(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer)),
  decrypt: jest.fn(() => Promise.resolve(new Uint8Array([72, 101, 108, 108, 111]).buffer))
};

// Set up crypto for both global and window
const mockCrypto = {
  subtle: mockSubtle,
  getRandomValues: jest.fn((arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  })
};

// Provide crypto in multiple ways for maximum compatibility
global.crypto = mockCrypto;
globalThis.crypto = mockCrypto;
global.window = global.window || {};
global.window.crypto = mockCrypto;

// Make crypto available globally for direct access
Object.defineProperty(global, 'crypto', {
  value: mockCrypto,
  writable: true,
  configurable: true
});

// Provide btoa/atob for base64 encoding
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');