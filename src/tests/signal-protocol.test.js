/**
 * @jest-environment jsdom
 */

import { TextEncoder, TextDecoder } from 'util';

// Mock Web Crypto API for Node.js environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock crypto.subtle API
const mockCrypto = {
    subtle: {
        generateKey: jest.fn(),
        exportKey: jest.fn(),
        importKey: jest.fn(),
        deriveBits: jest.fn(),
        deriveKey: jest.fn(),
        sign: jest.fn(),
        verify: jest.fn(),
    },
    getRandomValues: jest.fn()
};

// Mock the crypto global
Object.defineProperty(global, 'crypto', {
    value: mockCrypto,
    writable: true
});

// Mock the window.crypto as well for compatibility
Object.defineProperty(global, 'window', {
    value: { crypto: mockCrypto },
    writable: true
});

describe('Signal Protocol Implementation', () => {
    let signalProtocol;

    beforeEach(() => {
        jest.clearAllMocks();
        
        // Create a mock implementation that we'll test against
        signalProtocol = {
            keyParams: {
                name: "ECDH",
                namedCurve: "P-256"
            },
            hkdfParams: {
                name: "HKDF",
                hash: "SHA-256"
            }
        };
    });

    describe('generateSignalKeyPair', () => {
        test('should generate ECDH key pair with correct parameters', async () => {
            const mockKeyPair = {
                publicKey: { type: 'public' },
                privateKey: { type: 'private' }
            };

            mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);

            const generateSignalKeyPair = async () => {
                return await crypto.subtle.generateKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256"
                    },
                    true,
                    ["deriveKey", "deriveBits"]
                );
            };

            const result = await generateSignalKeyPair();

            expect(mockCrypto.subtle.generateKey).toHaveBeenCalledWith(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );
            expect(result).toEqual(mockKeyPair);
        });
    });

    describe('exportSignalPublicKey', () => {
        test('should export public key as raw bytes', async () => {
            const mockPublicKey = { type: 'public' };
            const mockRawKey = new ArrayBuffer(65); // P-256 uncompressed public key

            mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);

            const exportSignalPublicKey = async (publicKey) => {
                return await crypto.subtle.exportKey("raw", publicKey);
            };

            const result = await exportSignalPublicKey(mockPublicKey);

            expect(mockCrypto.subtle.exportKey).toHaveBeenCalledWith("raw", mockPublicKey);
            expect(result).toEqual(mockRawKey);
        });
    });

    describe('importSignalPublicKey', () => {
        test('should import public key from raw bytes', async () => {
            const mockKeyBytes = new ArrayBuffer(65);
            const mockImportedKey = { type: 'public' };

            mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);

            const importSignalPublicKey = async (keyBytes) => {
                return await crypto.subtle.importKey(
                    "raw",
                    keyBytes,
                    {
                        name: "ECDH",
                        namedCurve: "P-256"
                    },
                    false,
                    []
                );
            };

            const result = await importSignalPublicKey(mockKeyBytes);

            expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
                "raw",
                mockKeyBytes,
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                false,
                []
            );
            expect(result).toEqual(mockImportedKey);
        });
    });

    describe('performSignalDH', () => {
        test('should perform ECDH key agreement', async () => {
            const mockPrivateKey = { type: 'private' };
            const mockPublicKey = { type: 'public' };
            const mockSharedSecret = new ArrayBuffer(32);

            mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);

            const performSignalDH = async (privateKey, publicKey) => {
                return await crypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: publicKey
                    },
                    privateKey,
                    256
                );
            };

            const result = await performSignalDH(mockPrivateKey, mockPublicKey);

            expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
                {
                    name: "ECDH",
                    public: mockPublicKey
                },
                mockPrivateKey,
                256
            );
            expect(result).toEqual(mockSharedSecret);
        });
    });

    describe('signSignalData', () => {
        test('should sign data with ECDSA', async () => {
            const mockPrivateKey = { type: 'private' };
            const mockData = new Uint8Array([1, 2, 3, 4]);
            const mockSignature = new ArrayBuffer(64);

            mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

            const signSignalData = async (privateKey, data) => {
                return await crypto.subtle.sign(
                    {
                        name: "ECDSA",
                        hash: "SHA-256"
                    },
                    privateKey,
                    data
                );
            };

            const result = await signSignalData(mockPrivateKey, mockData);

            expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                mockPrivateKey,
                mockData
            );
            expect(result).toEqual(mockSignature);
        });
    });

    describe('verifySignalSignature', () => {
        test('should verify signature with ECDSA', async () => {
            const mockPublicKey = { type: 'public' };
            const mockSignature = new ArrayBuffer(64);
            const mockData = new Uint8Array([1, 2, 3, 4]);

            mockCrypto.subtle.verify.mockResolvedValue(true);

            const verifySignalSignature = async (publicKey, signature, data) => {
                return await crypto.subtle.verify(
                    {
                        name: "ECDSA",
                        hash: "SHA-256"
                    },
                    publicKey,
                    signature,
                    data
                );
            };

            const result = await verifySignalSignature(mockPublicKey, mockSignature, mockData);

            expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                mockPublicKey,
                mockSignature,
                mockData
            );
            expect(result).toBe(true);
        });
    });

    describe('deriveSignalKey', () => {
        test('should derive key using HKDF', async () => {
            const mockInputKeyMaterial = new ArrayBuffer(128);
            const mockSalt = new ArrayBuffer(32);
            const mockInfo = new TextEncoder().encode("Signal_Test");
            const mockPrk = { type: 'secret' };
            const mockDerivedKey = { type: 'secret' };

            mockCrypto.subtle.importKey.mockResolvedValue(mockPrk);
            mockCrypto.subtle.deriveKey.mockResolvedValue(mockDerivedKey);

            const deriveSignalKey = async (inputKeyMaterial, salt, info, length = 256) => {
                const prk = await crypto.subtle.importKey(
                    "raw",
                    inputKeyMaterial,
                    "HKDF",
                    false,
                    ["deriveKey"]
                );

                return await crypto.subtle.deriveKey(
                    {
                        name: "HKDF",
                        hash: "SHA-256",
                        salt: salt,
                        info: info
                    },
                    prk,
                    {
                        name: "AES-GCM",
                        length: length
                    },
                    true,
                    ["encrypt", "decrypt"]
                );
            };

            const result = await deriveSignalKey(mockInputKeyMaterial, mockSalt, mockInfo);

            expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
                "raw",
                mockInputKeyMaterial,
                "HKDF",
                false,
                ["deriveKey"]
            );

            expect(mockCrypto.subtle.deriveKey).toHaveBeenCalledWith(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: mockSalt,
                    info: mockInfo
                },
                mockPrk,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );

            expect(result).toEqual(mockDerivedKey);
        });
    });

    describe('concatSignalArrayBuffers', () => {
        test('should concatenate multiple ArrayBuffers', () => {
            const concatSignalArrayBuffers = (...buffers) => {
                const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
                const result = new Uint8Array(totalLength);
                let offset = 0;
                
                for (const buffer of buffers) {
                    result.set(new Uint8Array(buffer), offset);
                    offset += buffer.byteLength;
                }
                
                return result.buffer;
            };

            const buffer1 = new Uint8Array([1, 2]).buffer;
            const buffer2 = new Uint8Array([3, 4]).buffer;
            const buffer3 = new Uint8Array([5, 6]).buffer;

            const result = concatSignalArrayBuffers(buffer1, buffer2, buffer3);
            const resultArray = new Uint8Array(result);

            expect(resultArray).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
            expect(result.byteLength).toBe(6);
        });

        test('should handle empty buffers', () => {
            const concatSignalArrayBuffers = (...buffers) => {
                const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
                const result = new Uint8Array(totalLength);
                let offset = 0;
                
                for (const buffer of buffers) {
                    result.set(new Uint8Array(buffer), offset);
                    offset += buffer.byteLength;
                }
                
                return result.buffer;
            };

            const buffer1 = new Uint8Array([]).buffer;
            const buffer2 = new Uint8Array([1, 2]).buffer;

            const result = concatSignalArrayBuffers(buffer1, buffer2);
            const resultArray = new Uint8Array(result);

            expect(resultArray).toEqual(new Uint8Array([1, 2]));
        });
    });

    describe('bufferToSignalHex', () => {
        test('should convert ArrayBuffer to hex string', () => {
            const bufferToSignalHex = (buffer) => {
                return Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            };

            const buffer = new Uint8Array([255, 0, 128, 15]).buffer;
            const result = bufferToSignalHex(buffer);

            expect(result).toBe('ff00800f');
        });

        test('should handle empty buffer', () => {
            const bufferToSignalHex = (buffer) => {
                return Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            };

            const buffer = new Uint8Array([]).buffer;
            const result = bufferToSignalHex(buffer);

            expect(result).toBe('');
        });
    });

    describe('Signal User Integration Tests', () => {
        test('should initialize user with all required keys', async () => {
            const mockKeyPair = {
                publicKey: { type: 'public' },
                privateKey: { type: 'private' }
            };
            const mockRawKey = new ArrayBuffer(65);
            const mockSignature = new ArrayBuffer(64);

            mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);
            mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);
            mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

            const initializeSignalUser = async (name) => {
                // Generate identity key pair
                const identityKeyPair = await crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" },
                    true,
                    ["deriveKey", "deriveBits"]
                );

                // Generate signed prekey pair
                const signedPrekeyPair = await crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" },
                    true,
                    ["deriveKey", "deriveBits"]
                );

                // Generate signature for signed prekey
                const prekeyBytes = await crypto.subtle.exportKey("raw", signedPrekeyPair.publicKey);
                const signedPrekeySignature = await crypto.subtle.sign(
                    { name: "ECDSA", hash: "SHA-256" },
                    identityKeyPair.privateKey,
                    prekeyBytes
                );

                // Generate one-time prekeys
                const oneTimePrekeyPairs = [];
                for (let i = 0; i < 3; i++) {
                    const oneTimeKey = await crypto.subtle.generateKey(
                        { name: "ECDH", namedCurve: "P-256" },
                        true,
                        ["deriveKey", "deriveBits"]
                    );
                    oneTimePrekeyPairs.push(oneTimeKey);
                }

                return {
                    name,
                    identityKeyPair,
                    signedPrekeyPair,
                    signedPrekeySignature,
                    oneTimePrekeyPairs
                };
            };

            const user = await initializeSignalUser("Alice");

            expect(mockCrypto.subtle.generateKey).toHaveBeenCalledTimes(5); // identity + signed prekey + 3 one-time keys
            expect(mockCrypto.subtle.exportKey).toHaveBeenCalledTimes(1);
            expect(mockCrypto.subtle.sign).toHaveBeenCalledTimes(1);
            expect(user.name).toBe("Alice");
            expect(user.oneTimePrekeyPairs).toHaveLength(3);
        });

        test('should create valid public key bundle', async () => {
            const mockRawKey = new ArrayBuffer(65);
            mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);

            const getPublicKeyBundle = async (user) => {
                return {
                    identityKey: await crypto.subtle.exportKey("raw", user.identityKeyPair.publicKey),
                    signedPrekey: await crypto.subtle.exportKey("raw", user.signedPrekeyPair.publicKey),
                    signedPrekeySignature: user.signedPrekeySignature,
                    oneTimePrekey: user.oneTimePrekeyPairs.length > 0 ? 
                        await crypto.subtle.exportKey("raw", user.oneTimePrekeyPairs[0].publicKey) : null
                };
            };

            const mockUser = {
                identityKeyPair: { publicKey: 'identity' },
                signedPrekeyPair: { publicKey: 'signed' },
                signedPrekeySignature: new ArrayBuffer(64),
                oneTimePrekeyPairs: [{ publicKey: 'onetime' }]
            };

            const bundle = await getPublicKeyBundle(mockUser);

            expect(mockCrypto.subtle.exportKey).toHaveBeenCalledTimes(3);
            expect(bundle).toHaveProperty('identityKey');
            expect(bundle).toHaveProperty('signedPrekey');
            expect(bundle).toHaveProperty('signedPrekeySignature');
            expect(bundle).toHaveProperty('oneTimePrekey');
        });
    });

    describe('X3DH Key Exchange Integration Tests', () => {
        test('should perform complete key exchange with all DH computations', async () => {
            const mockKeyPair = { publicKey: 'pub', privateKey: 'priv' };
            const mockSharedSecret = new ArrayBuffer(32);
            const mockImportedKey = { type: 'public' };
            const mockDerivedKey = { type: 'secret' };
            const mockRawKey = new ArrayBuffer(65);

            mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);
            mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);
            mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);
            mockCrypto.subtle.deriveKey.mockResolvedValue(mockDerivedKey);
            mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);
            mockCrypto.subtle.verify.mockResolvedValue(true);

            const performX3DHKeyExchange = async (alice, bobBundle) => {
                // Verify Bob's signed prekey signature
                const bobIdentityKey = await crypto.subtle.importKey(
                    "raw", bobBundle.identityKey,
                    { name: "ECDH", namedCurve: "P-256" }, false, []
                );
                
                const isValidSignature = await crypto.subtle.verify(
                    { name: "ECDSA", hash: "SHA-256" },
                    bobIdentityKey, bobBundle.signedPrekeySignature, bobBundle.signedPrekey
                );

                if (!isValidSignature) {
                    throw new Error("Invalid signed prekey signature!");
                }

                // Generate ephemeral key pair
                const aliceEphemeralPair = await crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" },
                    true, ["deriveKey", "deriveBits"]
                );

                // Import Bob's keys
                const bobSignedPrekey = await crypto.subtle.importKey(
                    "raw", bobBundle.signedPrekey,
                    { name: "ECDH", namedCurve: "P-256" }, false, []
                );

                // Perform Triple DH
                const dh1 = await crypto.subtle.deriveBits(
                    { name: "ECDH", public: bobSignedPrekey },
                    alice.identityKeyPair.privateKey, 256
                );

                const dh2 = await crypto.subtle.deriveBits(
                    { name: "ECDH", public: bobIdentityKey },
                    aliceEphemeralPair.privateKey, 256
                );

                const dh3 = await crypto.subtle.deriveBits(
                    { name: "ECDH", public: bobSignedPrekey },
                    aliceEphemeralPair.privateKey, 256
                );

                // Concatenate DH outputs
                const dhOutputs = new ArrayBuffer(96); // 32 * 3 bytes

                // Derive master secret
                const prk = await crypto.subtle.importKey("raw", dhOutputs, "HKDF", false, ["deriveKey"]);
                const masterSecret = await crypto.subtle.deriveKey(
                    {
                        name: "HKDF", hash: "SHA-256",
                        salt: new ArrayBuffer(32),
                        info: new TextEncoder().encode("Signal_X3DH_Key_Derivation")
                    },
                    prk,
                    { name: "AES-GCM", length: 256 },
                    true, ["encrypt", "decrypt"]
                );

                return {
                    masterSecret: await crypto.subtle.exportKey("raw", masterSecret),
                    aliceEphemeralPublic: await crypto.subtle.exportKey("raw", aliceEphemeralPair.publicKey),
                    usedOneTimePrekey: false
                };
            };

            const mockAlice = {
                identityKeyPair: { privateKey: 'alice_identity_priv' }
            };

            const mockBobBundle = {
                identityKey: mockRawKey,
                signedPrekey: mockRawKey,
                signedPrekeySignature: new ArrayBuffer(64),
                oneTimePrekey: null
            };

            const result = await performX3DHKeyExchange(mockAlice, mockBobBundle);

            expect(mockCrypto.subtle.verify).toHaveBeenCalledTimes(1);
            expect(mockCrypto.subtle.generateKey).toHaveBeenCalledTimes(1);
            expect(mockCrypto.subtle.importKey).toHaveBeenCalledTimes(3);
            expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledTimes(3);
            expect(mockCrypto.subtle.deriveKey).toHaveBeenCalledTimes(1);
            expect(result).toHaveProperty('masterSecret');
            expect(result).toHaveProperty('aliceEphemeralPublic');
            expect(result).toHaveProperty('usedOneTimePrekey');
        });

        test('should handle one-time prekey usage correctly', async () => {
            const mockSharedSecret = new ArrayBuffer(32);
            const mockImportedKey = { type: 'public' };

            mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);
            mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);

            const performDHWithOneTimeKey = async (ephemeralPrivate, oneTimePublicBytes) => {
                if (!oneTimePublicBytes) return null;

                const oneTimePublic = await crypto.subtle.importKey(
                    "raw", oneTimePublicBytes,
                    { name: "ECDH", namedCurve: "P-256" }, false, []
                );

                return await crypto.subtle.deriveBits(
                    { name: "ECDH", public: oneTimePublic },
                    ephemeralPrivate, 256
                );
            };

            const mockEphemeralPrivate = { type: 'private' };
            const mockOneTimeBytes = new ArrayBuffer(65);

            const result = await performDHWithOneTimeKey(mockEphemeralPrivate, mockOneTimeBytes);

            expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
                "raw", mockOneTimeBytes,
                { name: "ECDH", namedCurve: "P-256" }, false, []
            );
            expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
                { name: "ECDH", public: mockImportedKey },
                mockEphemeralPrivate, 256
            );
            expect(result).toEqual(mockSharedSecret);
        });

        test('should handle missing one-time prekey gracefully', async () => {
            const performDHWithOneTimeKey = async (ephemeralPrivate, oneTimePublicBytes) => {
                if (!oneTimePublicBytes) return null;

                const oneTimePublic = await crypto.subtle.importKey(
                    "raw", oneTimePublicBytes,
                    { name: "ECDH", namedCurve: "P-256" }, false, []
                );

                return await crypto.subtle.deriveBits(
                    { name: "ECDH", public: oneTimePublic },
                    ephemeralPrivate, 256
                );
            };

            const mockEphemeralPrivate = { type: 'private' };
            const result = await performDHWithOneTimeKey(mockEphemeralPrivate, null);

            expect(result).toBeNull();
            expect(mockCrypto.subtle.importKey).not.toHaveBeenCalled();
            expect(mockCrypto.subtle.deriveBits).not.toHaveBeenCalled();
        });
    });

    describe('Error Handling', () => {
        test('should handle invalid signature verification', async () => {
            mockCrypto.subtle.verify.mockResolvedValue(false);

            const verifyPrekeySignature = async (identityKey, signature, prekeyData) => {
                const isValid = await crypto.subtle.verify(
                    { name: "ECDSA", hash: "SHA-256" },
                    identityKey, signature, prekeyData
                );

                if (!isValid) {
                    throw new Error("Invalid signed prekey signature!");
                }

                return true;
            };

            await expect(verifyPrekeySignature({}, new ArrayBuffer(64), new ArrayBuffer(65)))
                .rejects.toThrow("Invalid signed prekey signature!");
        });

        test('should handle crypto operation failures', async () => {
            mockCrypto.subtle.generateKey.mockRejectedValue(new Error("Crypto operation failed"));

            const generateKeyWithErrorHandling = async () => {
                try {
                    return await crypto.subtle.generateKey(
                        { name: "ECDH", namedCurve: "P-256" },
                        true, ["deriveKey", "deriveBits"]
                    );
                } catch (error) {
                    throw new Error(`Key generation failed: ${error.message}`);
                }
            };

            await expect(generateKeyWithErrorHandling())
                .rejects.toThrow("Key generation failed: Crypto operation failed");
        });
    });
});