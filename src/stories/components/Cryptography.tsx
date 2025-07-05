import React, { createContext, useContext, useState, useEffect } from "react";
import { sha3_512 } from "js-sha3";
import Chance from "chance";

// Create Context
const CryptographyContext = createContext(null);

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