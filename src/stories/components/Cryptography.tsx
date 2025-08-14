import React, { createContext, useContext, useState, useEffect } from "react";
import { sha3_512 } from "js-sha3";
import Chance from "chance";

// Create Context
const CryptographyContext = createContext<unknown>(null);

// Cryptographically Random String Generator
export const randomString = (additionalSalt = "") => {
    // Define the length of the random string
    const randomStringLength = 16; // You can change this value to generate a longer or shorter string

    // Generate a random array of uint8 values
    const randomValues = crypto.getRandomValues(
        new Uint8Array(randomStringLength),
    );

    // Convert random values to hexadecimal string
    const randomHex = Array.from(randomValues)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");

    // If additional salt is provided, concatenate it with the random string
    const randomString = additionalSalt ? additionalSalt + randomHex : randomHex;

    return randomString;
};

// CryptographyProvider Component
export const CryptographyProvider = ({ entropy = "", children }) => {
    const [salt, setSalt] = useState(randomString((entropy || "") + Date.now()));
    const [chance, setChance] = useState(new Chance(salt));

    useEffect(() => {
        const updateStates = async () => {
            try {
                const newSalt = await sha256Hash(entropy);
                setSalt(newSalt);
                setChance(new Chance(newSalt));
            } catch (error) {
                console.error('Error updating states:', error);
                // Keep existing values on error
            }
        };
        
        if (entropy) {
            updateStates();
        }
    }, [entropy]);

    const random = (additionalSalt = "") => randomString(additionalSalt + salt);

    // Hashing Methods
    const sha256Hash = async (input) => {
        // // Ensure the input is a string
        // if (typeof inputString !== 'string') throw new Error('Input must be a string');

        const inputString = JSON.stringify(input);

        // Convert the string to an ArrayBuffer
        const encoder = new TextEncoder();
        const data = encoder.encode(inputString);

        // Hash the data
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);

        // Convert the result to a hexadecimal string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");

        return hashHex;
    };

    const sha512Hash = async (input) => {
        // // Ensure the input is a string
        // if (typeof inputString !== 'string') throw new Error('Input must be a string');
        const inputString = JSON.stringify(input);

        // Convert the string to an ArrayBuffer
        const encoder = new TextEncoder();
        const data = encoder.encode(inputString);

        // Hash the data
        const hashBuffer = await crypto.subtle.digest("SHA-512", data);

        // Convert the result to a hexadecimal string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");

        return hashHex;
    };

    const sha3_512Hash = async (input) => {
        // // Ensure the input is a string
        // if (typeof inputString !== 'string') throw new Error('Input must be a string');
        const inputString = JSON.stringify(input);

        // Hash the data
        const hashHex = sha3_512(inputString);

        return hashHex;
    };

    // RSA Key Generation and Encryption/Decryption Methods
    const generateKeyPair = async () => {
        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 4096, // Can be 1024, 2048, or 4096
                    publicExponent: new Uint8Array([1, 0, 1]), // 65537 in bytes
                    hash: "SHA-256", // Can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                true, // Whether the key is extractable
                ["encrypt", "decrypt"], // Key usages
            );

            // Export keys to JWK format for storage/transmission
            const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
            const privateKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

            return {
                publicKey: publicKeyJWK,
                privateKey: privateKeyJWK,
            };
        } catch (error) {
            console.error("Error generating key pair:", error);
            throw error;
        }
    };

    const deserializePublicKey = async (key) => {
        try {
            // If key is already a JWK object, use it directly
            // If it's a string, parse it first
            const jwkKey = typeof key === 'string' ? JSON.parse(key) : key;
            
            // Validate that required JWK properties exist
            if (!jwkKey.kty) {
                throw new Error('Invalid JWK: missing "kty" property');
            }
            
            const publicKey = await crypto.subtle.importKey(
                "jwk", // Import format
                jwkKey, // The key in JWK format
                {
                    name: "RSA-OAEP", // Algorithm name
                    hash: "SHA-256", // Hash algorithm
                },
                true, // Extractable flag
                ["encrypt"], // Key usages
            );

            return publicKey;
        } catch (error) {
            console.error("Error deserializing public key:", error);
            throw error;
        }
    };

    const deserializePrivateKey = async (key) => {
        try {
            // If key is already a JWK object, use it directly
            // If it's a string, parse it first
            const jwkKey = typeof key === 'string' ? JSON.parse(key) : key;
            
            // Validate that required JWK properties exist
            if (!jwkKey.kty) {
                throw new Error('Invalid JWK: missing "kty" property');
            }
            
            const privateKey = await crypto.subtle.importKey(
                "jwk", // Import format
                jwkKey, // The key in JWK format
                {
                    name: "RSA-OAEP", // Algorithm name
                    hash: "SHA-256", // Hash algorithm
                },
                true, // Extractable flag
                ["decrypt"], // Key usages
            );

            return privateKey;
        } catch (error) {
            console.error("Error deserializing private key:", error);
            throw error;
        }
    };

    const encrypt = async (message, publicKey) => {
        const encodedMessage = new TextEncoder().encode(message);
        const encrypted = await window.crypto.subtle
            .encrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                publicKey,
                encodedMessage,
            )
            .catch((error) => {
                console.log("error", error);
            });

        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    };

    const decrypt = async (encryptedMessage, privateKey, passphrase) => {
        const buffer = Uint8Array.from(atob(encryptedMessage), (c) =>
            c.charCodeAt(0),
        );
        try {
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                privateKey,
                buffer,
            );
            const message = new TextDecoder().decode(decrypted);
            return message;
        } catch (error) {
            console.log("error", error);
            throw new Error(
                "Unable to decrypt message. Incorrect passphrase.",
                error,
            );
        }
    };

    // Symmetric Key Generation and Encryption/Decryption Methods
    const generateSymmetricKey = async () => {
        const key = await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256, // can be  128, 192, or 256
            },
            true, // whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"],
        );

        // Export key to JWK format for storage/transmission
        const keyJWK = await crypto.subtle.exportKey("jwk", key);
        return keyJWK;
    };

    const deserializeSymmetricKey = async (key) => {
        try {
            // If key is already a JWK object, use it directly
            // If it's a string, parse it first
            const jwkKey = typeof key === 'string' ? JSON.parse(key) : key;
            
            // Validate that required JWK properties exist for symmetric keys
            if (!jwkKey.kty) {
                throw new Error('Invalid JWK: missing "kty" property');
            }
            
            // Ensure the key type is correct for symmetric keys
            if (jwkKey.kty !== "oct") {
                jwkKey.kty = "oct";
            }
            
            const deSerializedSymmetricKey = await window.crypto.subtle.importKey(
                "jwk",
                jwkKey,
                {
                    name: "AES-GCM",
                },
                true,
                ["encrypt", "decrypt"],
            );

            return deSerializedSymmetricKey;
        } catch (error) {
            console.error("Error deserializing symmetric key:", error);
            throw error;
        }
    };

    const encryptWithSymmetricKey = async (message, key) => {
        const encodedMessage = new TextEncoder().encode(message);
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // must be 12 bytes

        const encrypted = await window.crypto.subtle
            .encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                key,
                encodedMessage,
            )
            .catch((error) => {
                console.log("error", error);
            });

        return {
            ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
        };
    };

    const decryptWithSymmetricKey = async (encryptedData, key) => {
        const { ciphertext, iv } = encryptedData;
        const buffer = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
        const ivBuffer = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));

        try {
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBuffer,
                },
                key,
                buffer,
            );
            const message = new TextDecoder().decode(decrypted);
            return message;
        } catch (error) {
            throw new Error("Unable to decrypt message. Incorrect key.");
        }
    };

    // Password-based File Encryption Functions
    const deriveKeyFromPassword = async (password, salt = null) => {
        const encoder = new TextEncoder();
        
        // Generate or use provided salt
        const actualSalt = salt || await crypto.subtle.digest(
            "SHA-256",
            encoder.encode(password)
        );
        
        // Import password as key material
        const passwordKey = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );
        
        // Derive AES-GCM key using PBKDF2
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: actualSalt,
                iterations: 100000, // Strong iteration count
                hash: "SHA-256",
            },
            passwordKey,
            {
                name: "AES-GCM",
                length: 256,
            },
            false, // Not extractable for security
            ["encrypt", "decrypt"]
        );
        
        return { key: derivedKey, salt: actualSalt };
    };

    const encryptFile = async (fileContent, password, fileName = '') => {
        try {
            const { key, salt } = await deriveKeyFromPassword(password);
            
            // Generate random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Convert file content to appropriate format
            let dataToEncrypt;
            if (typeof fileContent === 'string') {
                dataToEncrypt = new TextEncoder().encode(fileContent);
            } else if (fileContent instanceof ArrayBuffer) {
                dataToEncrypt = fileContent;
            } else if (fileContent instanceof File) {
                dataToEncrypt = await fileContent.arrayBuffer();
            } else {
                throw new Error('Unsupported file content type');
            }
            
            // Encrypt the file content
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                key,
                dataToEncrypt
            );
            
            // Return encrypted package
            return {
                encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
                iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
                salt: btoa(String.fromCharCode(...new Uint8Array(salt))),
                fileName: fileName,
                timestamp: new Date().toISOString(),
                originalSize: dataToEncrypt.byteLength
            };
        } catch (error) {
            console.error('Error encrypting file:', error);
            throw error;
        }
    };

    const decryptFile = async (encryptedPackage, password) => {
        try {
            const { encryptedData, iv, salt, fileName, originalSize } = encryptedPackage;
            
            // Convert base64 back to ArrayBuffer
            const saltBuffer = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
            const ivBuffer = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
            const dataBuffer = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            
            // Derive the same key using password and salt
            const { key } = await deriveKeyFromPassword(password, saltBuffer);
            
            // Decrypt the data
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBuffer,
                },
                key,
                dataBuffer
            );
            
            return {
                data: decryptedData,
                fileName: fileName,
                originalSize: originalSize,
                decryptedSize: decryptedData.byteLength
            };
        } catch (error) {
            console.error('Error decrypting file:', error);
            throw new Error('Failed to decrypt file. Check password and try again.');
        }
    };

    const encryptTextFile = async (textContent, password, fileName = 'encrypted.txt') => {
        return await encryptFile(textContent, password, fileName);
    };

    const decryptTextFile = async (encryptedPackage, password) => {
        const result = await decryptFile(encryptedPackage, password);
        const textContent = new TextDecoder().decode(result.data);
        return {
            ...result,
            textContent: textContent
        };
    };

    const encryptBinaryFile = async (file, password) => {
        if (!(file instanceof File)) {
            throw new Error('Expected File object for binary encryption');
        }
        
        const encryptedPackage = await encryptFile(file, password, file.name);
        return {
            ...encryptedPackage,
            mimeType: file.type,
            fileSize: file.size
        };
    };

    const decryptBinaryFile = async (encryptedPackage, password) => {
        const result = await decryptFile(encryptedPackage, password);
        return {
            ...result,
            blob: new Blob([result.data], { type: encryptedPackage.mimeType || 'application/octet-stream' }),
            mimeType: encryptedPackage.mimeType
        };
    };

    const createSecureFileDownload = (data, fileName, mimeType = 'application/octet-stream') => {
        let blob;
        if (data instanceof ArrayBuffer) {
            blob = new Blob([data], { type: mimeType });
        } else if (typeof data === 'string') {
            blob = new Blob([data], { type: 'text/plain' });
        } else {
            blob = data; // Assume it's already a Blob
        }
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const parseEncryptedFilePackage = async (file) => {
        try {
            // Read the file content
            const content = await file.text();
            
            // Parse as JSON
            const parsed = JSON.parse(content);
            
            // Validate required properties
            const requiredProperties = ['encryptedData', 'iv', 'salt', 'fileName', 'timestamp', 'originalSize'];
            for (const prop of requiredProperties) {
                if (!parsed.hasOwnProperty(prop)) {
                    throw new Error(`Missing required property: ${prop}`);
                }
            }
            
            // Validate data types
            if (typeof parsed.encryptedData !== 'string') {
                throw new Error('encryptedData must be a base64 string');
            }
            if (typeof parsed.iv !== 'string') {
                throw new Error('iv must be a base64 string');
            }
            if (typeof parsed.salt !== 'string') {
                throw new Error('salt must be a base64 string');
            }
            if (typeof parsed.fileName !== 'string') {
                throw new Error('fileName must be a string');
            }
            if (typeof parsed.originalSize !== 'number') {
                throw new Error('originalSize must be a number');
            }
            
            return {
                isValid: true,
                package: parsed,
                metadata: {
                    fileName: parsed.fileName,
                    originalSize: parsed.originalSize,
                    timestamp: parsed.timestamp,
                    type: parsed.type || 'unknown',
                    mimeType: parsed.mimeType || null
                }
            };
        } catch (error) {
            return {
                isValid: false,
                error: error.message,
                package: null,
                metadata: null
            };
        }
    };

    const decryptUploadedFile = async (encryptedFilePackage, password) => {
        try {
            // First validate the package
            const validation = await parseEncryptedFilePackage(encryptedFilePackage);
            if (!validation.isValid) {
                throw new Error(`Invalid encrypted file package: ${validation.error}`);
            }
            
            const { package: pkg, metadata } = validation;
            
            // Decrypt the file
            const decryptedResult = await decryptFile(pkg, password);
            
            // Return enhanced result with metadata
            return {
                ...decryptedResult,
                metadata: metadata,
                isTextFile: metadata.type === 'text' || metadata.mimeType?.startsWith('text/'),
                textContent: metadata.type === 'text' ? new TextDecoder().decode(decryptedResult.data) : null
            };
        } catch (error) {
            console.error('Error decrypting uploaded file:', error);
            throw new Error(`Failed to decrypt uploaded file: ${error.message}`);
        }
    };

    // Signal Protocol X3DH Key Exchange Implementation
    // Using X25519 for key agreement (matches actual Signal Protocol)
    const signalKeyParams = {
        name: "X25519"
    };
    
    const signalHkdfParams = {
        name: "HKDF",
        hash: "SHA-256"
    };

    const generateSignalKeyPair = async () => {
        return await crypto.subtle.generateKey(
            signalKeyParams,
            true,
            ["deriveBits"]
        );
    };

    const generateSignalSigningKeyPair = async () => {
        return await crypto.subtle.generateKey(
            {
                name: "Ed25519"  // Using Ed25519 for signatures (matches actual Signal Protocol)
            },
            true,
            ["sign", "verify"]
        );
    };

    const exportSignalPublicKey = async (publicKey) => {
        return await crypto.subtle.exportKey("raw", publicKey);
    };

    const importSignalPublicKey = async (keyBytes) => {
        return await crypto.subtle.importKey(
            "raw",
            keyBytes,
            signalKeyParams,
            true, // Make public keys extractable for Double Ratchet key comparisons
            []
        );
    };

    const importSignalSigningPublicKey = async (keyBytes) => {
        return await crypto.subtle.importKey(
            "raw",
            keyBytes,
            {
                name: "Ed25519"
            },
            false,
            ["verify"]
        );
    };

    const performSignalDH = async (privateKey, publicKey) => {
        console.log('🔄 Performing X25519 key agreement...');
        console.log('Private key algorithm:', privateKey?.algorithm?.name || 'X25519');
        console.log('Public key algorithm:', publicKey?.algorithm?.name || 'X25519');
        console.log('Private key usages:', privateKey?.usages || ['deriveKey']);
        console.log('Public key usages:', publicKey?.usages || ['deriveBits']);
        
        try {
            const result = await crypto.subtle.deriveBits(
                {
                    name: "X25519",
                    public: publicKey
                },
                privateKey,
                256  // X25519 always produces 256 bits (32 bytes)
            );
            console.log('✓ X25519 key agreement successful, output length:', result.byteLength);
            return result;
        } catch (error) {
            console.error('❌ X25519 key agreement failed:', error);
            throw error;
        }
    };

    const signSignalData = async (privateKey, data) => {
        return await crypto.subtle.sign(
            {
                name: "Ed25519"
            },
            privateKey,
            data
        );
    };

    const verifySignalSignature = async (publicKey, signature, data) => {
        console.log('🔍 Verifying Ed25519 signature...');
        console.log('Public key algorithm:', publicKey?.algorithm?.name || 'X25519');
        console.log('Public key usages:', publicKey?.usages || ['verify']);
        console.log('Signature length:', signature.byteLength);
        console.log('Data length:', data.byteLength);
        
        try {
            const result = await crypto.subtle.verify(
                {
                    name: "Ed25519"
                },
                publicKey,
                signature,
                data
            );
            console.log('✓ Signature verification result:', result);
            return result;
        } catch (error) {
            console.error('❌ Signature verification failed:', error);
            throw error;
        }
    };

    const deriveSignalKey = async (inputKeyMaterial, salt, info, length = 256) => {
        const prk = await crypto.subtle.importKey(
            "raw",
            inputKeyMaterial,
            signalHkdfParams.name,
            false,
            ["deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: signalHkdfParams.name,
                hash: signalHkdfParams.hash,
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

    const bufferToSignalHex = (buffer) => {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    };

    const initializeSignalUser = async (name) => {
        console.log(`🔐 [${name}] Starting user initialization...`);
        
        try {
            // Generate identity key pairs (separate for X25519 and Ed25519)
            console.log(`🔑 [${name}] Generating identity signing key pair (Ed25519)...`);
            const identitySigningKeyPair = await generateSignalSigningKeyPair();
            console.log(`✓ [${name}] Identity signing key pair generated:`, {
                publicKeyAlgorithm: identitySigningKeyPair.publicKey?.algorithm?.name || 'Ed25519',
                privateKeyAlgorithm: identitySigningKeyPair.privateKey?.algorithm?.name || 'Ed25519'
            });
            
            console.log(`🔑 [${name}] Generating identity X25519 key pair...`);
            const identityKeyPair = await generateSignalKeyPair();
            console.log(`✓ [${name}] Identity X25519 key pair generated:`, {
                publicKeyAlgorithm: identityKeyPair.publicKey?.algorithm?.name || 'X25519',
                privateKeyAlgorithm: identityKeyPair.privateKey?.algorithm?.name || 'X25519'
            });
            
            // Generate signed prekey pair
            console.log(`🔑 [${name}] Generating signed prekey pair...`);
            const signedPrekeyPair = await generateSignalKeyPair();
            console.log(`✓ [${name}] Signed prekey pair generated`);
            
            // Sign the prekey with identity signing key
            console.log(`📝 [${name}] Exporting signed prekey for signing...`);
            const prekeyBytes = await exportSignalPublicKey(signedPrekeyPair.publicKey);
            console.log(`📝 [${name}] Prekey bytes length:`, prekeyBytes.byteLength);
            
            console.log(`✍️ [${name}] Signing prekey with identity signing key...`);
            const signedPrekeySignature = await signSignalData(
                identitySigningKeyPair.privateKey,
                prekeyBytes
            );
            console.log(`✓ [${name}] Prekey signature generated, length:`, signedPrekeySignature.byteLength);

            // Generate one-time prekeys
            console.log(`🔑 [${name}] Generating one-time prekeys...`);
            const oneTimePrekeyPairs: CryptoKeyPair[] = [];
            for (let i = 0; i < 3; i++) {
                const oneTimeKey = await generateSignalKeyPair();
                oneTimePrekeyPairs.push(oneTimeKey);
                console.log(`✓ [${name}] One-time prekey ${i + 1}/3 generated`);
            }

            console.log(`✅ [${name}] User initialization completed successfully`);
            return {
                name,
                identityKeyPair, // X25519 key pair
                identitySigningKeyPair, // Ed25519 key pair
                signedPrekeyPair,
                signedPrekeySignature,
                oneTimePrekeyPairs
            };
        } catch (error) {
            console.error(`❌ [${name}] User initialization failed:`, error);
            throw error;
        }
    };

    const getSignalPublicKeyBundle = async (user) => {
        console.log(`📦 Creating public key bundle for ${user.name}...`);
        
        try {
            console.log('Exporting identity X25519 key...');
            const identityKey = await exportSignalPublicKey(user.identityKeyPair.publicKey);
            console.log('✓ Identity X25519 key exported, length:', identityKey.byteLength);
            
            console.log('Exporting identity signing key...');
            const identitySigningKey = await exportSignalPublicKey(user.identitySigningKeyPair.publicKey);
            console.log('✓ Identity signing key exported, length:', identitySigningKey.byteLength);
            
            console.log('Exporting signed prekey...');
            const signedPrekey = await exportSignalPublicKey(user.signedPrekeyPair.publicKey);
            console.log('✓ Signed prekey exported, length:', signedPrekey.byteLength);
            
            const oneTimePrekey = user.oneTimePrekeyPairs.length > 0 ? 
                await exportSignalPublicKey(user.oneTimePrekeyPairs[0].publicKey) : null;
            if (oneTimePrekey) {
                console.log('✓ One-time prekey exported, length:', oneTimePrekey.byteLength);
            } else {
                console.log('⚠️ No one-time prekey available');
            }

            const bundle = {
                identityKey, // X25519 key
                identitySigningKey, // Ed25519 key  
                signedPrekey,
                signedPrekeySignature: user.signedPrekeySignature,
                oneTimePrekey
            };
            
            console.log(`✅ Public key bundle created for ${user.name}`);
            return bundle;
        } catch (error) {
            console.error(`❌ Failed to create public key bundle for ${user.name}:`, error);
            throw error;
        }
    };

    const consumeSignalOneTimePrekey = (user) => {
        return user.oneTimePrekeyPairs.shift();
    };

    const performSignalX3DHKeyExchange = async (alice, bobBundle) => {
        console.log(`🤝 Starting X3DH key exchange between ${alice.name} and Bob...`);
        console.log('📦 Bob bundle keys available:', {
            hasIdentityKey: !!bobBundle.identityKey,
            hasIdentitySigningKey: !!bobBundle.identitySigningKey,
            hasSignedPrekey: !!bobBundle.signedPrekey,
            hasSignedPrekeySignature: !!bobBundle.signedPrekeySignature,
            hasOneTimePrekey: !!bobBundle.oneTimePrekey
        });

        try {
            // Step 1: Verify Bob's signed prekey signature using his signing key
            console.log('📝 Step 1: Importing Bob\'s identity signing key...');
            const bobIdentitySigningKey = await importSignalSigningPublicKey(bobBundle.identitySigningKey);
            console.log('✓ Bob\'s signing key imported, algorithm:', bobIdentitySigningKey?.algorithm?.name || 'Ed25519');
            
            console.log('🔍 Verifying Bob\'s signed prekey signature...');
            console.log('Signature length:', bobBundle.signedPrekeySignature.byteLength);
            console.log('Prekey data length:', bobBundle.signedPrekey.byteLength);
            
            const isValidSignature = await verifySignalSignature(
                bobIdentitySigningKey,
                bobBundle.signedPrekeySignature,
                bobBundle.signedPrekey
            );
            
            console.log('✓ Signature verification result:', isValidSignature);
            
            if (!isValidSignature) {
                throw new Error("Invalid signed prekey signature!");
            }

            // Step 2: Generate ephemeral key pair
            console.log('🔑 Step 2: Generating Alice\'s ephemeral key pair...');
            const aliceEphemeralPair = await generateSignalKeyPair();
            console.log('✓ Ephemeral key pair generated:', {
                publicAlgorithm: aliceEphemeralPair.publicKey?.algorithm?.name || 'X25519',
                privateAlgorithm: aliceEphemeralPair.privateKey?.algorithm?.name || 'X25519'
            });

            // Step 3: Import Bob's public keys for DH operations
            console.log('🔄 Step 3: Importing Bob\'s keys for DH operations...');
            
            console.log('Importing Bob\'s signed prekey...');
            const bobSignedPrekey = await importSignalPublicKey(bobBundle.signedPrekey);
            console.log('✓ Bob signed prekey imported:', bobSignedPrekey?.algorithm?.name || 'X25519');
            
            console.log('Importing Bob\'s identity key for DH...');
            const bobIdentityKeyDH = await importSignalPublicKey(bobBundle.identityKey);
            console.log('✓ Bob identity DH key imported:', bobIdentityKeyDH?.algorithm?.name || 'X25519');
            
            const bobOneTimePrekey = bobBundle.oneTimePrekey ? 
                await importSignalPublicKey(bobBundle.oneTimePrekey) : null;
            if (bobOneTimePrekey) {
                console.log('✓ Bob one-time prekey imported:', bobOneTimePrekey?.algorithm?.name || 'X25519');
            } else {
                console.log('⚠️ No one-time prekey available');
            }

            // Step 4: Perform the Triple (or Quadruple) Diffie-Hellman computation
            console.log('🔄 Step 4: Performing DH computations...');
            
            console.log('DH1: Alice_Identity_Private × Bob_SignedPrekey_Public');
            console.log('Alice identity private algorithm:', alice.identityKeyPair.privateKey?.algorithm?.name || 'X25519');
            console.log('Bob signed prekey public algorithm:', bobSignedPrekey?.algorithm?.name || 'X25519');
            const dh1 = await performSignalDH(
                alice.identityKeyPair.privateKey,
                bobSignedPrekey
            );
            console.log('✓ DH1 completed, output length:', dh1.byteLength);

            console.log('DH2: Alice_Ephemeral_Private × Bob_Identity_Public');
            console.log('Alice ephemeral private algorithm:', aliceEphemeralPair.privateKey?.algorithm?.name || 'X25519');
            console.log('Bob identity public algorithm:', bobIdentityKeyDH?.algorithm?.name || 'X25519');
            const dh2 = await performSignalDH(
                aliceEphemeralPair.privateKey,
                bobIdentityKeyDH
            );
            console.log('✓ DH2 completed, output length:', dh2.byteLength);

            console.log('DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public');
            const dh3 = await performSignalDH(
                aliceEphemeralPair.privateKey,
                bobSignedPrekey
            );
            console.log('✓ DH3 completed, output length:', dh3.byteLength);

            // DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (if available)
            let dh4: ArrayBuffer | null = null;
            if (bobOneTimePrekey) {
                console.log('DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public');
                dh4 = await performSignalDH(
                    aliceEphemeralPair.privateKey,
                    bobOneTimePrekey
                );
                console.log('✓ DH4 completed, output length:', dh4.byteLength);
            } else {
                console.log('⚠️ Skipping DH4 (no one-time prekey)');
            }

            // Step 5: Combine all DH outputs
            console.log('🔗 Step 5: Combining DH outputs...');
            
            // Log the individual DH outputs for comparison
            console.log('Alice DH outputs (hex):');
            console.log('  DH1:', bufferToSignalHex(dh1));
            console.log('  DH2:', bufferToSignalHex(dh2));
            console.log('  DH3:', bufferToSignalHex(dh3));
            if (dh4) console.log('  DH4:', bufferToSignalHex(dh4));
            
            const dhOutputs = dh4 ? 
                concatSignalArrayBuffers(dh1, dh2, dh3, dh4) :
                concatSignalArrayBuffers(dh1, dh2, dh3);
            console.log('✓ Combined DH outputs, total length:', dhOutputs.byteLength);

            // Step 6: Derive the master secret using HKDF
            console.log('🔑 Step 6: Deriving master secret using HKDF...');
            const salt = new ArrayBuffer(32); // 32 zero bytes
            const info = new TextEncoder().encode("Signal_X3DH_Key_Derivation");
            console.log('Salt length:', salt.byteLength);
            console.log('Info string:', new TextDecoder().decode(info));
            
            const masterSecret = await deriveSignalKey(dhOutputs, salt, info);
            console.log('✓ Master secret derived');
            
            const secretBytes = await crypto.subtle.exportKey("raw", masterSecret);
            console.log('✓ Master secret exported, length:', secretBytes.byteLength);
            console.log('🔐 Alice final secret:', bufferToSignalHex(secretBytes));

            const result = {
                masterSecret: secretBytes,
                aliceEphemeralPublic: await exportSignalPublicKey(aliceEphemeralPair.publicKey),
                usedOneTimePrekey: bobBundle.oneTimePrekey !== null
            };
            
            console.log('✅ X3DH key exchange completed successfully!');
            return result;
            
        } catch (error) {
            console.error('❌ X3DH key exchange failed:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    };

    const deriveSignalSharedSecret = async (bob, aliceEphemeralPublic, aliceIdentityPublic, usedOneTimePrekey, oneTimePrekeyBytes = null) => {
        console.log(`🔄 Bob deriving shared secret from Alice's message...`);
        console.log('Alice ephemeral public length:', aliceEphemeralPublic.byteLength);
        console.log('Alice identity public length:', aliceIdentityPublic.byteLength);
        console.log('Used one-time prekey:', usedOneTimePrekey);
        
        try {
            // Import Alice's public keys
            console.log('📥 Importing Alice\'s public keys...');
            const aliceEphemeral = await importSignalPublicKey(aliceEphemeralPublic);
            const aliceIdentity = await importSignalPublicKey(aliceIdentityPublic);
            console.log('✓ Alice\'s keys imported');

            // Perform the same DH computations (but from Bob's perspective)
            console.log('🔄 Bob performing DH computations...');
            
            // DH1: Bob_SignedPrekey_Private × Alice_Identity_Public
            console.log('Bob DH1: Bob_SignedPrekey_Private × Alice_Identity_Public');
            const dh1 = await performSignalDH(
                bob.signedPrekeyPair.privateKey,
                aliceIdentity
            );
            console.log('✓ Bob DH1 completed, output length:', dh1.byteLength);

            // DH2: Bob_Identity_Private × Alice_Ephemeral_Public  
            console.log('Bob DH2: Bob_Identity_Private × Alice_Ephemeral_Public');
            const dh2 = await performSignalDH(
                bob.identityKeyPair.privateKey,
                aliceEphemeral
            );
            console.log('✓ Bob DH2 completed, output length:', dh2.byteLength);

            // DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public
            console.log('Bob DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public');
            const dh3 = await performSignalDH(
                bob.signedPrekeyPair.privateKey,
                aliceEphemeral
            );
            console.log('✓ Bob DH3 completed, output length:', dh3.byteLength);

            // DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (if used)
            let dh4: ArrayBuffer | null = null;
            if (usedOneTimePrekey && oneTimePrekeyBytes && bob.oneTimePrekeyPairs.length > 0) {
                console.log('Bob DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public');
                console.log('Using provided one-time prekey bytes, length:', oneTimePrekeyBytes.byteLength);
                
                // Find the matching one-time prekey in Bob's collection
                let matchingKeyPair: CryptoKeyPair | null = null;
                for (const keyPair of bob.oneTimePrekeyPairs) {
                    const publicKeyBytes = await exportSignalPublicKey(keyPair.publicKey);
                    const publicKeyHex = bufferToSignalHex(publicKeyBytes);
                    const providedKeyHex = bufferToSignalHex(oneTimePrekeyBytes);
                    
                    console.log('Comparing keys:');
                    console.log('  Bob key:', publicKeyHex.substring(0, 32) + '...');
                    console.log('  Used key:', providedKeyHex.substring(0, 32) + '...');
                    
                    if (publicKeyHex === providedKeyHex) {
                        matchingKeyPair = keyPair;
                        console.log('✓ Found matching one-time prekey in Bob\'s collection');
                        break;
                    }
                }
                
                if (matchingKeyPair) {
                    dh4 = await performSignalDH(
                        matchingKeyPair.privateKey,
                        aliceEphemeral
                    );
                    console.log('✓ Bob DH4 completed, output length:', dh4.byteLength);
                } else {
                    console.error('❌ Could not find matching one-time prekey in Bob\'s collection!');
                    console.log('Bob has', bob.oneTimePrekeyPairs.length, 'one-time prekeys available');
                    console.log('Looking for key:', bufferToSignalHex(oneTimePrekeyBytes));
                    for (let i = 0; i < bob.oneTimePrekeyPairs.length; i++) {
                        const keyBytes = await exportSignalPublicKey(bob.oneTimePrekeyPairs[i].publicKey);
                        console.log(`Bob key ${i}:`, bufferToSignalHex(keyBytes));
                    }
                    throw new Error('One-time prekey mismatch');
                }
            } else {
                console.log('⚠️ Bob skipping DH4 (no one-time prekey used, no prekey bytes provided, or no keys available)');
                console.log('  usedOneTimePrekey:', usedOneTimePrekey);
                console.log('  oneTimePrekeyBytes:', !!oneTimePrekeyBytes);
                console.log('  bob.oneTimePrekeyPairs.length:', bob.oneTimePrekeyPairs.length);
            }

            // Combine DH outputs in the same order
            console.log('🔗 Bob combining DH outputs...');
            const dhOutputs = dh4 ? 
                concatSignalArrayBuffers(dh1, dh2, dh3, dh4) :
                concatSignalArrayBuffers(dh1, dh2, dh3);
            console.log('✓ Bob combined DH outputs, total length:', dhOutputs.byteLength);

            // Log the individual DH outputs for comparison
            console.log('Bob DH outputs (hex):');
            console.log('  DH1:', bufferToSignalHex(dh1));
            console.log('  DH2:', bufferToSignalHex(dh2));
            console.log('  DH3:', bufferToSignalHex(dh3));
            if (dh4) console.log('  DH4:', bufferToSignalHex(dh4));

            // Derive the same master secret
            console.log('🔑 Bob deriving master secret using HKDF...');
            const salt = new ArrayBuffer(32);
            const info = new TextEncoder().encode("Signal_X3DH_Key_Derivation");
            console.log('Bob salt length:', salt.byteLength);
            console.log('Bob info string:', new TextDecoder().decode(info));
            
            const masterSecret = await deriveSignalKey(dhOutputs, salt, info);
            console.log('✓ Bob master secret derived');
            
            const secretBytes = await crypto.subtle.exportKey("raw", masterSecret);
            console.log('✓ Bob master secret exported, length:', secretBytes.byteLength);
            console.log('🔐 Bob final secret:', bufferToSignalHex(secretBytes));

            return secretBytes;
        } catch (error) {
            console.error('❌ Bob shared secret derivation failed:', error);
            throw error;
        }
    };

    const demonstrateSignalProtocol = async () => {
        try {
            // Create two users
            const alice = await initializeSignalUser("Alice");
            const bob = await initializeSignalUser("Bob");

            // Get Bob's public key bundle
            const bobBundle = await getSignalPublicKeyBundle(bob);

            // Perform the X3DH key exchange
            const exchangeResult = await performSignalX3DHKeyExchange(alice, bobBundle);

            // Verify Bob can derive the same secret
            const aliceIdentityPublic = await exportSignalPublicKey(alice.identityKeyPair.publicKey);
            
            // Get the one-time prekey that was actually used
            const usedOneTimePrekey = exchangeResult.usedOneTimePrekey ? bobBundle.oneTimePrekey : null;
            
            const bobSecret = await deriveSignalSharedSecret(
                bob,
                exchangeResult.aliceEphemeralPublic,
                aliceIdentityPublic,
                exchangeResult.usedOneTimePrekey,
                usedOneTimePrekey // Pass the actual prekey that was used
            );

            // Now consume Bob's one-time prekey after both sides have used it
            if (exchangeResult.usedOneTimePrekey) {
                consumeSignalOneTimePrekey(bob);
            }

            // Verify both parties have the same secret
            const aliceSecretHex = bufferToSignalHex(exchangeResult.masterSecret);
            const bobSecretHex = bufferToSignalHex(bobSecret);
            
            const success = aliceSecretHex === bobSecretHex;
            
            return {
                success,
                aliceSecret: aliceSecretHex,
                bobSecret: bobSecretHex,
                usedOneTimePrekey: exchangeResult.usedOneTimePrekey,
                alice,
                bob,
                exchangeResult
            };
        } catch (error) {
            console.error("Error during Signal Protocol demonstration:", error);
            throw error;
        }
    };

    // Double Ratchet Protocol Implementation
    // Following the Signal Protocol specification for ongoing secure messaging
    
    const DOUBLE_RATCHET_INFO_MESSAGE_KEY = new TextEncoder().encode("DoubleRatchet_MessageKey");
    const DOUBLE_RATCHET_INFO_CHAIN_KEY = new TextEncoder().encode("DoubleRatchet_ChainKey");
    const DOUBLE_RATCHET_INFO_ROOT_KEY = new TextEncoder().encode("DoubleRatchet_RootKey");
    const DOUBLE_RATCHET_CHAIN_KEY_CONSTANT = new Uint8Array(1).fill(0x02);
    const DOUBLE_RATCHET_MESSAGE_KEY_CONSTANT = new Uint8Array(1).fill(0x01);
    const MAX_SKIPPED_MESSAGE_KEYS = 1000;

    // HKDF implementation for Double Ratchet
    const doubleRatchetHKDF = async (salt, inputKeyMaterial, info, length = 32) => {
        // Extract phase
        const saltKey = await crypto.subtle.importKey(
            "raw",
            salt.length > 0 ? salt : new Uint8Array(32), // Use zero salt if empty
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        
        const prk = await crypto.subtle.sign("HMAC", saltKey, inputKeyMaterial);
        
        // Expand phase
        const prkKey = await crypto.subtle.importKey(
            "raw",
            prk,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        
        const okm = new Uint8Array(length);
        let t = new Uint8Array(0);
        let counter = 1;
        let pos = 0;
        
        while (pos < length) {
            const input = new Uint8Array(t.length + info.length + 1);
            input.set(t);
            input.set(info, t.length);
            input[t.length + info.length] = counter;
            
            t = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, input));
            const remaining = length - pos;
            const copyLength = Math.min(t.length, remaining);
            okm.set(t.subarray(0, copyLength), pos);
            pos += copyLength;
            counter++;
        }
        
        return okm.buffer;
    };

    // HMAC-SHA256 for chain key updates
    const doubleRatchetHMAC = async (key, data) => {
        const hmacKey = await crypto.subtle.importKey(
            "raw",
            key,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        
        return await crypto.subtle.sign("HMAC", hmacKey, data);
    };

    // Initialize Double Ratchet state from X3DH shared secret
    const initializeDoubleRatchet = async (sharedSecret, isInitiator, remotePublicKey = null) => {
        console.log(`🔄 Initializing Double Ratchet (${isInitiator ? 'Initiator' : 'Responder'})`);
        
        // Derive initial root key from X3DH shared secret
        const initialRootKey = await doubleRatchetHKDF(
            new Uint8Array(0), // Empty salt
            sharedSecret,
            DOUBLE_RATCHET_INFO_ROOT_KEY,
            32
        );
        
        console.log('✓ Initial root key derived from X3DH secret');
        
        const state = {
            // Core ratchet state
            rootKey: initialRootKey,
            sendingChainKey: null,
            receivingChainKey: null,
            
            // DH key pairs
            sendingDHKeyPair: null,
            receivingDHPublicKey: remotePublicKey,
            
            // Message counters
            sendingMessageNumber: 0,
            receivingMessageNumber: 0,
            previousChainLength: 0,
            
            // Skipped message keys storage
            skippedMessageKeys: new Map(), // Format: "dhKey:messageNum" -> messageKey
            
            // State flags
            isInitiator,
            initialized: Date.now()
        };
        
        if (isInitiator) {
            // Initiator: Generate initial DH key pair and sending chain
            console.log('🔑 Generating initial DH key pair for initiator');
            state.sendingDHKeyPair = await generateSignalKeyPair();
            
            if (remotePublicKey) {
                // Perform initial DH and derive sending chain
                const dhOutput = await performSignalDH(
                    state.sendingDHKeyPair.privateKey,
                    remotePublicKey
                );
                
                const hkdfOutput = await doubleRatchetHKDF(
                    new Uint8Array(initialRootKey),
                    dhOutput,
                    DOUBLE_RATCHET_INFO_CHAIN_KEY,
                    64 // 32 bytes root key + 32 bytes chain key
                );
                
                state.rootKey = hkdfOutput.slice(0, 32);
                state.sendingChainKey = hkdfOutput.slice(32, 64);
                console.log('✓ Initial sending chain derived for initiator');
            } else {
                // No remote key provided - initiator starts conversation with direct key derivation
                // Bob will need to derive his receiving chain to match this sending chain
                const hkdfOutput = await doubleRatchetHKDF(
                    new Uint8Array(0), // Empty salt for direct derivation
                    new Uint8Array(initialRootKey),
                    DOUBLE_RATCHET_INFO_CHAIN_KEY,
                    64 // 32 bytes root key + 32 bytes chain key
                );
                
                state.rootKey = hkdfOutput.slice(0, 32);
                state.sendingChainKey = hkdfOutput.slice(32, 64);
                console.log('✓ Initial sending chain derived directly from root key:', {
                    rootKeyHex: Array.from(new Uint8Array(state.rootKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
                    sendingChainKeyHex: Array.from(new Uint8Array(state.sendingChainKey)).map(b => b.toString(16).padStart(2, '0')).join('')
                });
            }
        } else {
            // Responder: Start with receiving mode, will create sending chain on first send
            console.log('📥 Responder initialized, waiting for first message');
        }
        
        console.log('✅ Double Ratchet state initialized successfully');
        return state;
    };

    // Derive message key from chain key
    const deriveMessageKey = async (chainKey) => {
        const messageKey = await doubleRatchetHMAC(chainKey, DOUBLE_RATCHET_MESSAGE_KEY_CONSTANT);
        return new Uint8Array(messageKey);
    };

    // Derive next chain key from current chain key
    const deriveNextChainKey = async (chainKey) => {
        const nextChainKey = await doubleRatchetHMAC(chainKey, DOUBLE_RATCHET_CHAIN_KEY_CONSTANT);
        return new Uint8Array(nextChainKey);
    };

    // Perform DH ratchet step (when receiving new DH public key)
    const performDHRatchetStep = async (state, newRemotePublicKey) => {
        console.log('🔄 Performing DH ratchet step');
        
        // Save current receiving chain info for skipped messages
        state.previousChainLength = state.receivingMessageNumber;
        state.receivingMessageNumber = 0;
        state.receivingDHPublicKey = newRemotePublicKey;
        
        // Generate a receiving DH key pair if we don't have one
        if (!state.sendingDHKeyPair) {
            state.sendingDHKeyPair = await generateSignalKeyPair();
        }
        
        // Export public keys for detailed logging (safely handle non-extractable keys)
        let ourDHPublicKey, remoteDHPublicKey;
        try {
            ourDHPublicKey = await exportSignalPublicKey(state.sendingDHKeyPair.publicKey);
            remoteDHPublicKey = await exportSignalPublicKey(newRemotePublicKey);
        } catch (error) {
            // Keys may not be extractable - use placeholder for logging
            ourDHPublicKey = new Uint8Array(32).fill(0);
            remoteDHPublicKey = new Uint8Array(32).fill(0);
            console.log('⚠️ Could not export keys for logging (non-extractable)');
        }
        
        // Correct Double Ratchet DH ratchet step
        // The key insight: Alice and Bob must derive the SAME chain keys from the SAME DH operations
        
        // Step 1: Derive the receiving chain key that matches what the sender used
        // The sender encrypted using DH(their_private, our_current_public)
        // So we decrypt using DH(our_current_private, their_public) - same DH operation!
        
        let receivingDHOutput;
        // Check if this is the responder's first message from the initiator
        const isResponderFirstReceive = !state.receivingChainKey && state.receivingMessageNumber === 0 && !state.sendingDHKeyPair;
        
        if (isResponderFirstReceive) {
            console.log('🔄 First receive: matching initiator\'s direct root key derivation (responder only)');
            
            // Alice derived: HKDF(empty_salt, rootKey, CHAIN_KEY_INFO) -> [newRootKey, sendingChain]
            // Bob must derive the exact same way to get the matching receiving chain
            const hkdfResult = await doubleRatchetHKDF(
                new Uint8Array(0), // Empty salt - same as initiator used
                new Uint8Array(state.rootKey), // Same root key as initiator had
                DOUBLE_RATCHET_INFO_CHAIN_KEY,
                64 // 32 bytes new root key + 32 bytes chain key
            );
            
            // Update our root key to match initiator's updated root key
            state.rootKey = hkdfResult.slice(0, 32);
            // Set receiving chain to match initiator's sending chain
            state.receivingChainKey = hkdfResult.slice(32, 64);
            
            console.log('🔄 Receiving chain set to match initiator\'s sending chain:', {
                receivingChainKeyHex: Array.from(new Uint8Array(state.receivingChainKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
                updatedRootKeyHex: Array.from(new Uint8Array(state.rootKey)).map(b => b.toString(16).padStart(2, '0')).join('')
            });
            
            // Generate our sending key pair for future messages
            console.log('🔑 Generating DH key pair for responder\'s future sending');
            state.sendingDHKeyPair = await generateSignalKeyPair();
            
            // Skip the DH calculation for receiving - we already set receivingChainKey above
            receivingDHOutput = null;
        } else if (state.sendingDHKeyPair) {
            console.log('🔄 Deriving receiving chain from: DH(our_current_private, their_public)');
            receivingDHOutput = await performSignalDH(
                state.sendingDHKeyPair.privateKey,
                newRemotePublicKey
            );
        } else {
            // Fallback case - should not happen in normal operation
            console.log('⚠️ Unexpected case: no sending DH key pair and not first receive');
            state.sendingDHKeyPair = await generateSignalKeyPair();
            receivingDHOutput = await performSignalDH(
                state.sendingDHKeyPair.privateKey,
                newRemotePublicKey
            );
        }
        
        // If we already set the receiving chain above (Bob's first receive), skip this
        if (!state.receivingChainKey && receivingDHOutput) {
            // Derive receiving chain key from the DH output
            const hkdfReceiving = await doubleRatchetHKDF(
                new Uint8Array(state.rootKey),
                receivingDHOutput,
                DOUBLE_RATCHET_INFO_CHAIN_KEY,
                64
            );
            state.rootKey = hkdfReceiving.slice(0, 32);
            state.receivingChainKey = hkdfReceiving.slice(32, 64);
            
            console.log('🔄 DH ratchet step - receiving chain established:', {
                rootKeyHex: Array.from(new Uint8Array(state.rootKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
                receivingChainKeyHex: Array.from(new Uint8Array(state.receivingChainKey)).map(b => b.toString(16).padStart(2, '0')).join('')
            });
        } else if (receivingDHOutput === null) {
            console.log('🔄 Skipping receiving chain derivation - already set above');
        }
        
        // Step 2: Generate NEW DH key pair and derive sending chain
        // This will be used for our future messages
        // CRITICAL: Always generate a NEW key pair for the DH ratchet step
        console.log('🔑 Generating NEW DH key pair for ratchet step');
        state.sendingDHKeyPair = await generateSignalKeyPair();
        state.sendingMessageNumber = 0;
        
        // Derive sending chain from our NEW DH key pair
        const sendingDHOutput = await performSignalDH(
            state.sendingDHKeyPair.privateKey,
            newRemotePublicKey
        );
        
        const hkdfSending = await doubleRatchetHKDF(
            new Uint8Array(state.rootKey),
            sendingDHOutput,
            DOUBLE_RATCHET_INFO_CHAIN_KEY,
            64
        );
        
        state.rootKey = hkdfSending.slice(0, 32);
        state.sendingChainKey = hkdfSending.slice(32, 64);
        
        console.log('🔄 DH ratchet step - sending chain established:', {
            newRootKeyHex: Array.from(new Uint8Array(state.rootKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
            sendingChainKeyHex: Array.from(new Uint8Array(state.sendingChainKey)).map(b => b.toString(16).padStart(2, '0')).join('')
        });
        
        console.log('✓ DH ratchet step completed');
    };

    // Skip message keys for out-of-order messages
    const skipMessageKeys = async (state, until) => {
        console.log(`⏭️ Skipping message keys from ${state.receivingMessageNumber} to ${until}`);
        
        if (state.receivingChainKey && state.receivingMessageNumber < until) {
            if (until - state.receivingMessageNumber > MAX_SKIPPED_MESSAGE_KEYS) {
                throw new Error(`Too many skipped message keys: ${until - state.receivingMessageNumber}`);
            }
            
            const dhPublicKeyHex = state.receivingDHPublicKey ? 
                bufferToSignalHex(await exportSignalPublicKey(state.receivingDHPublicKey)) : 
                'null';
            
            let chainKey = new Uint8Array(state.receivingChainKey);
            
            while (state.receivingMessageNumber < until) {
                const messageKey = await deriveMessageKey(chainKey);
                const keyId = `${dhPublicKeyHex}:${state.receivingMessageNumber}`;
                state.skippedMessageKeys.set(keyId, messageKey);
                
                chainKey = await deriveNextChainKey(chainKey);
                state.receivingMessageNumber++;
                
                console.log(`📝 Saved skipped message key for ${keyId}`);
            }
            
            state.receivingChainKey = chainKey;
        }
    };

    // Encrypt message using Double Ratchet
    const doubleRatchetEncrypt = async (state, plaintext) => {
        console.log(`🔒 Encrypting message #${state.sendingMessageNumber} with Double Ratchet`);
        
        if (!state.sendingChainKey) {
            throw new Error('No sending chain key available - cannot encrypt');
        }
        
        // Derive message key
        const messageKey = await deriveMessageKey(new Uint8Array(state.sendingChainKey));
        // Get DH public key for logging
        const dhPublicKeyBuffer = await exportSignalPublicKey(state.sendingDHKeyPair.publicKey);
        const dhPublicKeyBytes = new Uint8Array(dhPublicKeyBuffer);
        
        console.log('🔑 Alice encryption - Chain and message keys:', {
            chainKeyHex: Array.from(new Uint8Array(state.sendingChainKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
            messageKeyHex: Array.from(messageKey).map(b => b.toString(16).padStart(2, '0')).join(''),
            sendingDHPublicKeyHex: Array.from(dhPublicKeyBytes).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(''),
            messageNumber: state.sendingMessageNumber,
            previousChainLength: state.previousChainLength
        });
        
        // Prepare additional authenticated data (AAD) - using already exported key
        const aad = new Uint8Array(dhPublicKeyBytes.length + 8); // DH key + 2 uint32s
        aad.set(dhPublicKeyBytes);
        
        // Add message number and previous chain length as AAD
        const view = new DataView(aad.buffer, dhPublicKeyBytes.length);
        view.setUint32(0, state.sendingMessageNumber, true);
        view.setUint32(4, state.previousChainLength, true);
        
        // Encrypt with AES-GCM
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        console.log('🔒 Attempting AES-GCM encryption with:', {
            keyLength: messageKey.length,
            ivLength: iv.length,
            aadLength: aad.length,
            plaintextLength: plaintextBytes.length
        });
        
        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            messageKey,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            cryptoKey,
            plaintextBytes
        );
        
        // Update sending chain key
        state.sendingChainKey = await deriveNextChainKey(new Uint8Array(state.sendingChainKey));
        
        const messageEnvelope = {
            dhPublicKey: dhPublicKeyBytes,
            messageNumber: state.sendingMessageNumber,
            previousChainLength: state.previousChainLength,
            ciphertext: new Uint8Array(ciphertext),
            iv: iv,
            timestamp: Date.now()
        };
        
        state.sendingMessageNumber++;
        
        console.log(`✅ Message encrypted successfully (msg #${state.sendingMessageNumber - 1})`);
        
        // Securely delete message key
        messageKey.fill(0);
        
        return messageEnvelope;
    };

    // Decrypt message using Double Ratchet
    const doubleRatchetDecrypt = async (state, messageEnvelope) => {
        console.log(`🔓 Decrypting message #${messageEnvelope.messageNumber} with Double Ratchet`);
        
        const { dhPublicKey, messageNumber, previousChainLength, ciphertext, iv } = messageEnvelope;
        const dhPublicKeyHex = bufferToSignalHex(dhPublicKey);
        
        // Check for skipped message key first
        const skippedKeyId = `${dhPublicKeyHex}:${messageNumber}`;
        let messageKey = state.skippedMessageKeys.get(skippedKeyId);
        
        if (messageKey) {
            console.log(`📋 Using skipped message key for message ${messageNumber}`);
            state.skippedMessageKeys.delete(skippedKeyId);
        } else {
            // Check if this is a new DH ratchet step
            const currentDhKeyHex = state.receivingDHPublicKey ? 
                bufferToSignalHex(await exportSignalPublicKey(state.receivingDHPublicKey)) : 
                null;
            
            if (dhPublicKeyHex !== currentDhKeyHex) {
                console.log('🔄 New DH public key detected, performing ratchet step');
                
                // Skip message keys for current chain if needed
                await skipMessageKeys(state, state.receivingMessageNumber);
                
                // Perform DH ratchet step
                const remotePublicKey = await importSignalPublicKey(dhPublicKey);
                await performDHRatchetStep(state, remotePublicKey);
            }
            
            // Skip message keys if needed
            await skipMessageKeys(state, messageNumber);
            
            // Derive message key
            if (!state.receivingChainKey) {
                throw new Error('No receiving chain key available - cannot decrypt');
            }
            
            // Store original chain key for logging
            const originalChainKey = new Uint8Array(state.receivingChainKey);
            
            messageKey = await deriveMessageKey(originalChainKey);
            state.receivingChainKey = await deriveNextChainKey(originalChainKey);
            const currentMessageNumber = state.receivingMessageNumber;
            state.receivingMessageNumber++;
            
            // Safe key export for logging
            let receivingDHPublicKeyHex = 'none';
            if (state.receivingDHPublicKey) {
                try {
                    const exportedKey = await exportSignalPublicKey(state.receivingDHPublicKey);
                    receivingDHPublicKeyHex = Array.from(new Uint8Array(exportedKey)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
                } catch (error) {
                    receivingDHPublicKeyHex = 'non-extractable';
                }
            }
            
            console.log('🔑 Bob decryption - Chain and message keys:', {
                originalChainKeyHex: Array.from(originalChainKey).map(b => b.toString(16).padStart(2, '0')).join(''),
                messageKeyHex: Array.from(messageKey).map(b => b.toString(16).padStart(2, '0')).join(''),
                newChainKeyHex: Array.from(new Uint8Array(state.receivingChainKey)).map(b => b.toString(16).padStart(2, '0')).join(''),
                receivingDHPublicKeyHex,
                messageNumber: currentMessageNumber
            });
        }
        
        // Prepare AAD for verification
        const aad = new Uint8Array(dhPublicKey.length + 8);
        aad.set(new Uint8Array(dhPublicKey));
        const view = new DataView(aad.buffer, dhPublicKey.length);
        view.setUint32(0, messageNumber, true);
        view.setUint32(4, previousChainLength, true);
        
        // Decrypt with AES-GCM
        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            messageKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        
        try {
            console.log('🔓 Attempting AES-GCM decryption with:', {
                keyLength: messageKey.length,
                ivLength: iv.length,
                aadLength: aad.length,
                ciphertextLength: ciphertext.length
            });
            
            const plaintext = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: aad },
                cryptoKey,
                ciphertext
            );
            
            const plaintextString = new TextDecoder().decode(plaintext);
            
            console.log(`✅ Message decrypted successfully: "${plaintextString}"`);
            
            // Securely delete message key
            messageKey.fill(0);
            
            return plaintextString;
        } catch (error) {
            console.error('❌ Message decryption failed:', error);
            throw new Error('Message decryption failed - authentication failed');
        }
    };

    // Serialize Double Ratchet state for storage
    const serializeDoubleRatchetState = async (state) => {
        const serialized = {
            rootKey: bufferToSignalHex(state.rootKey),
            sendingChainKey: state.sendingChainKey ? bufferToSignalHex(state.sendingChainKey) : null,
            receivingChainKey: state.receivingChainKey ? bufferToSignalHex(state.receivingChainKey) : null,
            sendingDHPublicKey: state.sendingDHKeyPair ? 
                bufferToSignalHex(await exportSignalPublicKey(state.sendingDHKeyPair.publicKey)) : null,
            receivingDHPublicKey: state.receivingDHPublicKey ?
                bufferToSignalHex(await exportSignalPublicKey(state.receivingDHPublicKey)) : null,
            sendingMessageNumber: state.sendingMessageNumber,
            receivingMessageNumber: state.receivingMessageNumber,
            previousChainLength: state.previousChainLength,
            isInitiator: state.isInitiator,
            initialized: state.initialized,
            skippedMessageKeysCount: state.skippedMessageKeys.size
        };
        
        return JSON.stringify(serialized);
    };

    // Clean up old skipped message keys to prevent memory bloat
    const cleanupSkippedMessageKeys = (state, maxAge = 7 * 24 * 60 * 60 * 1000) => {
        const now = Date.now();
        const keysToDelete = [];
        
        // In a real implementation, you'd track the age of each skipped key
        // For now, just limit the total number
        if (state.skippedMessageKeys.size > MAX_SKIPPED_MESSAGE_KEYS * 0.8) {
            const keys = Array.from(state.skippedMessageKeys.keys());
            const deleteCount = state.skippedMessageKeys.size - MAX_SKIPPED_MESSAGE_KEYS / 2;
            
            for (let i = 0; i < deleteCount; i++) {
                keysToDelete.push(keys[i]);
            }
        }
        
        keysToDelete.forEach(key => {
            state.skippedMessageKeys.delete(key);
        });
        
        if (keysToDelete.length > 0) {
            console.log(`🧹 Cleaned up ${keysToDelete.length} old skipped message keys`);
        }
    };

    // Demonstrate Double Ratchet conversation
    const demonstrateDoubleRatchet = async () => {
        try {
            console.log('🚀 Starting Double Ratchet demonstration...');
            
            // Initialize X3DH for shared secret
            const alice = await initializeSignalUser("Alice");
            const bob = await initializeSignalUser("Bob");
            const bobBundle = await getSignalPublicKeyBundle(bob);
            const exchangeResult = await performSignalX3DHKeyExchange(alice, bobBundle);
            
            // Initialize Double Ratchet states
            // Alice starts as initiator, Bob as responder - both start fresh
            const aliceState = await initializeDoubleRatchet(
                exchangeResult.masterSecret, 
                true
            );
            
            const bobState = await initializeDoubleRatchet(
                exchangeResult.masterSecret,
                false
            );
            
            console.log('📊 Double Ratchet states initialized');
            
            // Simulate conversation
            const conversation = [];
            
            // Alice sends first message
            const msg1 = await doubleRatchetEncrypt(aliceState, "Hello Bob! This is our first Double Ratchet message! 🔒");
            conversation.push({ from: 'Alice', envelope: msg1 });
            
            const decrypted1 = await doubleRatchetDecrypt(bobState, msg1);
            console.log(`Bob decrypted: "${decrypted1}"`);
            
            // Bob replies (he now has sending chain from DH ratchet)
            const msg2 = await doubleRatchetEncrypt(bobState, "Hi Alice! The Double Ratchet is working perfectly! 🎉");
            conversation.push({ from: 'Bob', envelope: msg2 });
            
            const decrypted2 = await doubleRatchetDecrypt(aliceState, msg2);
            console.log(`Alice decrypted: "${decrypted2}"`);
            
            // Alice sends multiple messages
            const msg3 = await doubleRatchetEncrypt(aliceState, "Each message gets a new key! 🔑");
            conversation.push({ from: 'Alice', envelope: msg3 });
            
            const msg4 = await doubleRatchetEncrypt(aliceState, "Forward secrecy is maintained! ⚡");
            conversation.push({ from: 'Alice', envelope: msg4 });
            
            // Decrypt in order
            const decrypted3 = await doubleRatchetDecrypt(bobState, msg3);
            const decrypted4 = await doubleRatchetDecrypt(bobState, msg4);
            
            console.log(`Bob decrypted msg3: "${decrypted3}"`);
            console.log(`Bob decrypted msg4: "${decrypted4}"`);
            
            // Test out-of-order delivery
            const msg5 = await doubleRatchetEncrypt(aliceState, "Message 5 - sent first");
            const msg6 = await doubleRatchetEncrypt(aliceState, "Message 6 - sent second");
            
            // Bob receives message 6 first (simulating network delay)
            const decrypted6 = await doubleRatchetDecrypt(bobState, msg6);
            const decrypted5 = await doubleRatchetDecrypt(bobState, msg5);
            
            console.log(`Bob decrypted msg6 first: "${decrypted6}"`);
            console.log(`Bob decrypted msg5 second: "${decrypted5}"`);
            
            conversation.push({ from: 'Alice', envelope: msg5 });
            conversation.push({ from: 'Alice', envelope: msg6 });
            
            const result = {
                success: true,
                aliceState: await serializeDoubleRatchetState(aliceState),
                bobState: await serializeDoubleRatchetState(bobState),
                conversation,
                messagesExchanged: conversation.length,
                demonstration: {
                    forwardSecrecy: true,
                    outOfOrderHandling: true,
                    dhRatcheting: true,
                    chainKeyUpdating: true
                }
            };
            
            console.log('✅ Double Ratchet demonstration completed successfully');
            return result;
            
        } catch (error) {
            console.error('❌ Double Ratchet demonstration failed:', error);
            throw error;
        }
    };

    // Exported Methods Bundle
    const cryptographyMethods = {
        randomString,
        sha256Hash,
        sha512Hash,
        sha3_512Hash,
        generateKeyPair,
        deserializePublicKey,
        deserializePrivateKey,
        encrypt,
        decrypt,
        generateSymmetricKey,
        deserializeSymmetricKey,
        encryptWithSymmetricKey,
        decryptWithSymmetricKey,
        // Password-based file encryption
        deriveKeyFromPassword,
        encryptFile,
        decryptFile,
        encryptTextFile,
        decryptTextFile,
        encryptBinaryFile,
        decryptBinaryFile,
        createSecureFileDownload,
        parseEncryptedFilePackage,
        decryptUploadedFile,
        // Signal Protocol X3DH functions
        generateSignalKeyPair,
        generateSignalSigningKeyPair,
        exportSignalPublicKey,
        importSignalPublicKey,
        importSignalSigningPublicKey,
        performSignalDH,
        signSignalData,
        verifySignalSignature,
        deriveSignalKey,
        concatSignalArrayBuffers,
        bufferToSignalHex,
        initializeSignalUser,
        getSignalPublicKeyBundle,
        consumeSignalOneTimePrekey,
        performSignalX3DHKeyExchange,
        deriveSignalSharedSecret,
        demonstrateSignalProtocol,
        // Double Ratchet Protocol functions
        initializeDoubleRatchet,
        doubleRatchetEncrypt,
        doubleRatchetDecrypt,
        serializeDoubleRatchetState,
        demonstrateDoubleRatchet,
        cleanupSkippedMessageKeys,
        // Add more methods as needed
        chance,
    };

    return (
        <CryptographyContext.Provider value={cryptographyMethods}>
            {children}
        </CryptographyContext.Provider>
    );
};

// Custom Hook to use Cryptography
export const useCryptography = () => {
    return useContext(CryptographyContext);
};

export default CryptographyProvider;