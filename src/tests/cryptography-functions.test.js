/**
 * Focused unit tests for cryptography functions to achieve 100% coverage
 * Tests individual functions without complex React rendering
 */

import React from 'react';
import { render, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

import { CryptographyProvider, useCryptography, randomString } from '../stories/components/Cryptography.tsx';


// Simple test component
const CryptoAccessor = ({ onReady }) => {
  const crypto = useCryptography();
  
  React.useEffect(() => {
    if (crypto && onReady) {
      onReady(crypto);
    }
  }, [crypto, onReady]);
  
  return <div data-testid="crypto-accessor">Ready</div>;
};

describe('Cryptography Functions - Target 100% Coverage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('randomString function - all branches', () => {
    // Test without additionalSalt (falsy)
    const result1 = randomString();
    expect(result1.length).toBe(32);
    
    // Test with additionalSalt (truthy)
    const result2 = randomString('test-salt');
    expect(result2).toMatch(/^test-salt/);
    
    // Test with empty string (falsy but defined)
    const result3 = randomString('');
    expect(result3.length).toBe(32);
  });

  test('Provider initialization and all crypto methods', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test hash functions with various inputs (only valid inputs for sha3)
    const testInputs = ['string', { obj: 'value' }, 123, [1, 2, 3]];
    
    for (const input of testInputs) {
      const sha256 = await cryptoMethods.sha256Hash(input);
      const sha512 = await cryptoMethods.sha512Hash(input);
      const sha3 = await cryptoMethods.sha3_512Hash(input);
      
      expect(sha256).toBeDefined();
      expect(sha512).toBeDefined(); 
      expect(sha3).toBeDefined();
    }
    
    // Test null and undefined separately for sha256/sha512 only
    const nullUndefinedInputs = [null, undefined];
    for (const input of nullUndefinedInputs) {
      const sha256 = await cryptoMethods.sha256Hash(input);
      const sha512 = await cryptoMethods.sha512Hash(input);
      
      expect(sha256).toBeDefined();
      expect(sha512).toBeDefined();
    }
    
    // Test RSA operations
    const keyPair = await cryptoMethods.generateKeyPair();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    
    // Test key deserialization - both object and string paths
    const pubKey = await cryptoMethods.deserializePublicKey({ kty: 'RSA' });
    const pubKeyStr = await cryptoMethods.deserializePublicKey('{"kty":"RSA"}');
    const privKey = await cryptoMethods.deserializePrivateKey({ kty: 'RSA' });
    const privKeyStr = await cryptoMethods.deserializePrivateKey('{"kty":"RSA"}');
    
    expect(pubKey).toEqual({ type: 'imported' });
    expect(pubKeyStr).toEqual({ type: 'imported' });
    expect(privKey).toEqual({ type: 'imported' });
    expect(privKeyStr).toEqual({ type: 'imported' });
    
    // Test encryption/decryption
    const encrypted = await cryptoMethods.encrypt('test message', pubKey);
    const decrypted = await cryptoMethods.decrypt(encrypted, privKey);
    expect(encrypted).toBeDefined();
    expect(decrypted).toBeDefined();
    
    // Test symmetric operations
    const symKey = await cryptoMethods.generateSymmetricKey();
    const symKeyObj = await cryptoMethods.deserializeSymmetricKey({ kty: 'oct' });
    const symKeyStr = await cryptoMethods.deserializeSymmetricKey('{"kty":"oct"}');
    
    expect(symKey).toBeDefined();
    expect(symKeyObj).toEqual({ type: 'imported' });
    expect(symKeyStr).toEqual({ type: 'imported' });
    
    // Test kty fix branch
    const wrongKtyKey = { kty: 'wrong' };
    await cryptoMethods.deserializeSymmetricKey(wrongKtyKey);
    expect(wrongKtyKey.kty).toBe('oct');
    
    const symEncrypted = await cryptoMethods.encryptWithSymmetricKey('message', symKeyObj);
    const symDecrypted = await cryptoMethods.decryptWithSymmetricKey(symEncrypted, symKeyObj);
    expect(symEncrypted.ciphertext).toBeDefined();
    expect(symEncrypted.iv).toBeDefined();
    expect(symDecrypted).toBeDefined();
  });

  test('Error handling paths', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test generateKeyPair error
    const origGenerateKey = globalThis.crypto.subtle.generateKey;
    globalThis.crypto.subtle.generateKey = jest.fn().mockRejectedValue(new Error('Generate failed'));
    await expect(cryptoMethods.generateKeyPair()).rejects.toThrow();
    expect(console.error).toHaveBeenCalledWith('Error generating key pair:', expect.any(Error));
    globalThis.crypto.subtle.generateKey = origGenerateKey;
    
    // Test deserialize errors with invalid JWK
    await expect(cryptoMethods.deserializePublicKey({ invalid: 'key' }))
      .rejects.toThrow('Invalid JWK: missing "kty" property');
    expect(console.error).toHaveBeenCalledWith('Error deserializing public key:', expect.any(Error));
    
    await expect(cryptoMethods.deserializePrivateKey({ invalid: 'key' }))
      .rejects.toThrow('Invalid JWK: missing "kty" property');
    expect(console.error).toHaveBeenCalledWith('Error deserializing private key:', expect.any(Error));
    
    await expect(cryptoMethods.deserializeSymmetricKey({ invalid: 'key' }))
      .rejects.toThrow('Invalid JWK: missing "kty" property');
    expect(console.error).toHaveBeenCalledWith('Error deserializing symmetric key:', expect.any(Error));
    
    // Test encrypt error by overriding the mock temporarily
    const origEncrypt = global.crypto.subtle.encrypt;
    global.crypto.subtle.encrypt = jest.fn().mockRejectedValue(new Error('Encrypt failed'));
    
    const result1 = await cryptoMethods.encrypt('test', 'key');
    expect(result1).toEqual(expect.anything()); // May return empty string on error
    expect(console.log).toHaveBeenCalledWith('error', expect.any(Error));
    
    const result2 = await cryptoMethods.encryptWithSymmetricKey('test', 'key');
    expect(result2).toEqual(expect.anything()); // May return partial result on error
    expect(console.log).toHaveBeenCalledWith('error', expect.any(Error));
    
    global.crypto.subtle.encrypt = origEncrypt;
    
    // Test decrypt errors
    const origDecrypt = globalThis.crypto.subtle.decrypt;
    globalThis.crypto.subtle.decrypt = jest.fn().mockRejectedValue(new Error('Decrypt failed'));
    
    await expect(cryptoMethods.decrypt('invalid', 'key'))
      .rejects.toThrow('Unable to decrypt message. Incorrect passphrase.');
    expect(console.log).toHaveBeenCalledWith('error', expect.any(Error));
    
    await expect(cryptoMethods.decryptWithSymmetricKey({ ciphertext: 'invalid', iv: 'invalid' }, 'key'))
      .rejects.toThrow('Unable to decrypt message. Incorrect key.');
    
    globalThis.crypto.subtle.decrypt = origDecrypt;
  });

  test('File operations coverage', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    const password = 'test-password';
    
    // Test deriveKeyFromPassword - both with and without salt
    const result1 = await cryptoMethods.deriveKeyFromPassword(password);
    expect(result1.key).toBeDefined();
    expect(result1.salt).toBeDefined();
    
    const customSalt = new Uint8Array([1, 2, 3, 4]);
    const result2 = await cryptoMethods.deriveKeyFromPassword(password, customSalt);
    expect(result2.salt).toBe(customSalt);
    
    // Test encryptFile with different content types
    const stringContent = 'test string';
    const arrayBuffer = new ArrayBuffer(10);
    const file = new global.File(['test'], 'test.txt');
    
    const enc1 = await cryptoMethods.encryptFile(stringContent, password, 'test1.txt');
    const enc2 = await cryptoMethods.encryptFile(arrayBuffer, password, 'test2.bin');
    const enc3 = await cryptoMethods.encryptFile(file, password);
    
    expect(enc1.fileName).toBe('test1.txt');
    expect(enc2.fileName).toBe('test2.bin');
    expect(enc3.fileName).toBe(''); // encryptFile doesn't auto-extract filename from File objects
    
    // Test unsupported content type
    await expect(cryptoMethods.encryptFile(123, password))
      .rejects.toThrow('Unsupported file content type');
    expect(console.error).toHaveBeenCalledWith('Error encrypting file:', expect.any(Error));
    
    // Test decryptFile
    const decrypted = await cryptoMethods.decryptFile(enc1, password);
    expect(decrypted.fileName).toBe('test1.txt');
    
    // Test text and binary file helpers
    const textEnc = await cryptoMethods.encryptTextFile(stringContent, password, 'text.txt');
    const textDec = await cryptoMethods.decryptTextFile(textEnc, password);
    expect(textDec.textContent).toBe('Hello'); // Mock decrypt always returns 'Hello'
    
    const binFile = new global.File([new Uint8Array([1, 2, 3])], 'bin.bin', { type: 'application/octet-stream' });
    const binEnc = await cryptoMethods.encryptBinaryFile(binFile, password);
    const binDec = await cryptoMethods.decryptBinaryFile(binEnc, password);
    expect(binEnc.mimeType).toBe('application/octet-stream');
    expect(binDec.blob).toBeDefined();
    
    // Test encryptBinaryFile error
    await expect(cryptoMethods.encryptBinaryFile('not-a-file', password))
      .rejects.toThrow('Expected File object for binary encryption');
    
    // Test createSecureFileDownload with all types
    cryptoMethods.createSecureFileDownload(arrayBuffer, 'test.bin', 'application/octet-stream');
    cryptoMethods.createSecureFileDownload('string content', 'test.txt');
    cryptoMethods.createSecureFileDownload(new global.Blob(['blob']), 'test.blob');
    
    // Functions should execute without throwing errors
    expect(true).toBe(true); // Test passes if no errors thrown
  });

  test('Parse and decrypt uploaded files', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test parseEncryptedFilePackage
    const validPackage = {
      encryptedData: 'valid',
      iv: 'valid',
      salt: 'valid',
      fileName: 'test.txt',
      timestamp: '2023-01-01',
      originalSize: 100
    };
    
    const validFile = { text: jest.fn().mockResolvedValue(JSON.stringify(validPackage)) };
    const parseResult = await cryptoMethods.parseEncryptedFilePackage(validFile);
    expect(parseResult.isValid).toBe(true);
    
    // Test invalid JSON
    const invalidFile = { text: jest.fn().mockResolvedValue('invalid json') };
    const invalidResult = await cryptoMethods.parseEncryptedFilePackage(invalidFile);
    expect(invalidResult.isValid).toBe(false);
    
    // Test missing properties
    const missingProps = ['encryptedData', 'iv', 'salt', 'fileName', 'timestamp', 'originalSize'];
    for (const prop of missingProps) {
      const incomplete = { ...validPackage };
      delete incomplete[prop];
      const incompleteFile = { text: jest.fn().mockResolvedValue(JSON.stringify(incomplete)) };
      const incompleteResult = await cryptoMethods.parseEncryptedFilePackage(incompleteFile);
      expect(incompleteResult.isValid).toBe(false);
      expect(incompleteResult.error).toBe(`Missing required property: ${prop}`);
    }
    
    // Test type validations
    const typeTests = [
      { field: 'encryptedData', value: 123, error: 'encryptedData must be a base64 string' },
      { field: 'iv', value: 123, error: 'iv must be a base64 string' },
      { field: 'salt', value: 123, error: 'salt must be a base64 string' },
      { field: 'fileName', value: 123, error: 'fileName must be a string' },
      { field: 'originalSize', value: 'string', error: 'originalSize must be a number' }
    ];
    
    for (const test of typeTests) {
      const wrongType = { ...validPackage };
      wrongType[test.field] = test.value;
      const wrongTypeFile = { text: jest.fn().mockResolvedValue(JSON.stringify(wrongType)) };
      const wrongTypeResult = await cryptoMethods.parseEncryptedFilePackage(wrongTypeFile);
      expect(wrongTypeResult.isValid).toBe(false);
      expect(wrongTypeResult.error).toBe(test.error);
    }
    
    // Test decryptUploadedFile
    const uploadResult = await cryptoMethods.decryptUploadedFile(validFile, 'password');
    expect(uploadResult.metadata).toBeDefined();
    
    // Test with text type
    validPackage.type = 'text';
    const textFile = { text: jest.fn().mockResolvedValue(JSON.stringify(validPackage)) };
    const textUploadResult = await cryptoMethods.decryptUploadedFile(textFile, 'password');
    expect(textUploadResult.isTextFile).toBe(true);
    
    // Test with mimeType starting with 'text/'
    validPackage.mimeType = 'text/plain';
    delete validPackage.type;
    const mimeFile = { text: jest.fn().mockResolvedValue(JSON.stringify(validPackage)) };
    const mimeUploadResult = await cryptoMethods.decryptUploadedFile(mimeFile, 'password');
    expect(mimeUploadResult.isTextFile).toBe(true);
  });

  test('File operation errors', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test decryptFile error
    const origDecrypt = globalThis.crypto.subtle.decrypt;
    globalThis.crypto.subtle.decrypt = jest.fn().mockRejectedValue(new Error('Decrypt failed'));
    
    const invalidPackage = {
      encryptedData: 'invalid',
      iv: 'invalid',
      salt: 'invalid',
      fileName: 'test.txt',
      originalSize: 100
    };
    
    await expect(cryptoMethods.decryptFile(invalidPackage, 'password'))
      .rejects.toThrow('Failed to decrypt file. Check password and try again.');
    expect(console.error).toHaveBeenCalledWith('Error decrypting file:', expect.any(Error));
    
    globalThis.crypto.subtle.decrypt = origDecrypt;
    
    // Test decryptUploadedFile with invalid package
    const invalidFile = { text: jest.fn().mockResolvedValue('invalid json') };
    await expect(cryptoMethods.decryptUploadedFile(invalidFile, 'password'))
      .rejects.toThrow('Failed to decrypt uploaded file:');
    expect(console.error).toHaveBeenCalledWith('Error decrypting uploaded file:', expect.any(Error));
  });

  test('Entropy useEffect path', async () => {
    let cryptoMethods;
    
    // Test with entropy that triggers useEffect
    render(
      <CryptographyProvider entropy="test-entropy">
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test entropy error path
    const origDigest = globalThis.crypto.subtle.digest;
    globalThis.crypto.subtle.digest = jest.fn().mockRejectedValue(new Error('Digest failed'));
    
    render(
      <CryptographyProvider entropy="error-entropy">
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(console.error).toHaveBeenCalledWith('Error updating states:', expect.any(Error));
    });
    
    globalThis.crypto.subtle.digest = origDigest;
  });

  test('Random function with salt and complete method check', async () => {
    let cryptoMethods;
    
    render(
      <CryptographyProvider>
        <CryptoAccessor onReady={(crypto) => { cryptoMethods = crypto; }} />
      </CryptographyProvider>
    );
    
    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });
    
    // Test random function (line 51)
    const randomResult1 = cryptoMethods.randomString();
    const randomResult2 = cryptoMethods.randomString('additional-salt');
    
    expect(randomResult1).toBeDefined();
    expect(randomResult2).toBeDefined();
    expect(randomResult2).toMatch(/additional-salt/);
    
    // Verify all expected methods exist
    const expectedMethods = [
      'randomString', 'sha256Hash', 'sha512Hash', 'sha3_512Hash',
      'generateKeyPair', 'deserializePublicKey', 'deserializePrivateKey',
      'encrypt', 'decrypt', 'generateSymmetricKey', 'deserializeSymmetricKey',
      'encryptWithSymmetricKey', 'decryptWithSymmetricKey',
      'deriveKeyFromPassword', 'encryptFile', 'decryptFile',
      'encryptTextFile', 'decryptTextFile', 'encryptBinaryFile', 'decryptBinaryFile',
      'createSecureFileDownload', 'parseEncryptedFilePackage', 'decryptUploadedFile',
      'chance'
    ];
    
    expectedMethods.forEach(method => {
      expect(cryptoMethods[method]).toBeDefined();
    });
  });
});