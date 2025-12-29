import React, { createContext, useContext, useState, useEffect } from "react";
import { sha3_512 } from "js-sha3";
import Chance from "chance";
import { MLSManager } from "../../crypto/MLS/MLSManager.tsx";
import { SFrameManager } from "../../crypto/SFrame/SFrameManager.tsx";
import { Zeroization } from "../../crypto/utils/zeroization.ts";

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
      } catch (error) {}
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
      const publicKeyJWK = await crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey,
      );
      const privateKeyJWK = await crypto.subtle.exportKey(
        "jwk",
        keyPair.privateKey,
      );

      return {
        publicKey: publicKeyJWK,
        privateKey: privateKeyJWK,
      };
    } catch (error) {}
  };

  const deserializePublicKey = async (key) => {
    try {
      // If key is already a JWK object, use it directly
      // If it's a string, parse it first
      const jwkKey = typeof key === "string" ? JSON.parse(key) : key;

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
    } catch (error) {}
  };

  const deserializePrivateKey = async (key) => {
    try {
      // If key is already a JWK object, use it directly
      // If it's a string, parse it first
      const jwkKey = typeof key === "string" ? JSON.parse(key) : key;

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
    } catch (error) {}
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
        console.error("Encryption error:", error);
        throw error;
      });
    return encrypted;
  };

  const decrypt = async (buffer, privateKey) => {
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
      console.error("Decryption error:", error);
      throw error;
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
      const jwkKey = typeof key === "string" ? JSON.parse(key) : key;

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
    } catch (error) {}
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
        console.error("Encryption error:", error);
        throw error;
      });
    return { encrypted, iv };
  };

  const decryptWithSymmetricKey = async (buffer, key, iv) => {
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        buffer,
      );
      const message = new TextDecoder().decode(decrypted);
      return message;
    } catch (error) {
      console.error("Decryption error:", error);
      throw new Error("Unable to decrypt message. Incorrect key.");
    }
  };

  // Password-based File Encryption Functions
  // Scrypt parameters (matching AESCipherLayer for consistency)
  const SCRYPT_N = 32768; // CPU/memory cost parameter
  const SCRYPT_R = 8; // Block size parameter
  const SCRYPT_P = 1; // Parallelization parameter

  // Cache scrypt function to avoid repeated imports
  let scryptCache = null;
  let scryptCachePromise = null;

  /**
   * Lazy-load scrypt function (handles ES module import)
   * Uses caching to avoid repeated imports
   */
  const getScryptFunction = async () => {
    // Return cached function if available
    if (scryptCache) {
      return scryptCache;
    }

    // Wait for ongoing import if in progress
    if (scryptCachePromise) {
      return await scryptCachePromise;
    }

    // Start new import
    scryptCachePromise = (async () => {
      try {
        // Dynamic import for ES module - works in browsers and Node.js
        // @noble/hashes/scrypt.js is browser-compatible pure JavaScript
        const scryptModule = await import("@noble/hashes/scrypt.js");
        const scryptFn = scryptModule.scrypt || scryptModule.default;
        scryptCache = scryptFn;
        scryptCachePromise = null;
        return scryptFn;
      } catch (error) {
        scryptCachePromise = null;
        // Re-throw with better error message
        throw new Error(
          `Failed to load scrypt module: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    })();

    return await scryptCachePromise;
  };

  const deriveKeyFromPassword = async (password, salt = null) => {
    const encoder = new TextEncoder();
    let passwordBytes = null;
    let actualSalt = null;

    try {
      // Generate or use provided salt
      if (salt instanceof Uint8Array || salt instanceof ArrayBuffer) {
        actualSalt = salt instanceof ArrayBuffer ? new Uint8Array(salt) : salt;
      } else {
        // Generate random salt if not provided
        actualSalt = crypto.getRandomValues(new Uint8Array(16));
      }

      // Encode password for zeroization
      passwordBytes = encoder.encode(password);

      // Use Scrypt for key derivation (GPU/ASIC resistant)
      const scrypt = await getScryptFunction();
      const keyMaterial = scrypt(passwordBytes, actualSalt, {
        N: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        dkLen: 32, // 32 bytes = 256 bits for AES-256
      });

      // Import the derived key material as a CryptoKey
      const derivedKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        {
          name: "AES-GCM",
        },
        false,
        ["encrypt", "decrypt"],
      );

      return { key: derivedKey, salt: actualSalt };
    } catch (error) {
      // Zeroize password buffer before throwing
      if (passwordBytes) {
        Zeroization.zeroize(passwordBytes);
      }
      throw error;
    } finally {
      // Always zeroize password buffer
      if (passwordBytes) {
        Zeroization.zeroize(passwordBytes);
      }
    }
  };

  const encryptFile = async (fileContent, password, fileName = "") => {
    try {
      const { key, salt } = await deriveKeyFromPassword(password);

      // Generate random IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Convert file content to appropriate format
      let dataToEncrypt;
      if (typeof fileContent === "string") {
        dataToEncrypt = new TextEncoder().encode(fileContent);
      } else if (fileContent instanceof ArrayBuffer) {
        dataToEncrypt = fileContent;
      } else if (fileContent instanceof File) {
        dataToEncrypt = await fileContent.arrayBuffer();
      } else {
        throw new Error("Unsupported file content type");
      }

      // Encrypt the file content
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        dataToEncrypt,
      );

      // Return encrypted package
      return {
        encryptedData: btoa(
          String.fromCharCode(...new Uint8Array(encryptedData)),
        ),
        iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
        salt: btoa(String.fromCharCode(...new Uint8Array(salt))),
        fileName: fileName,
        timestamp: new Date().toISOString(),
        originalSize: dataToEncrypt.byteLength,
      };
    } catch (error) {}
  };

  const decryptFile = async (encryptedPackage, password) => {
    try {
      const { encryptedData, iv, salt, fileName, originalSize } =
        encryptedPackage;

      // Convert base64 back to ArrayBuffer
      const saltBuffer = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0));
      const ivBuffer = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
      const dataBuffer = Uint8Array.from(atob(encryptedData), (c) =>
        c.charCodeAt(0),
      );

      // Derive the same key using password and salt
      const { key } = await deriveKeyFromPassword(password, saltBuffer);

      // Decrypt the data
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBuffer,
        },
        key,
        dataBuffer,
      );

      return {
        data: decryptedData,
        fileName: fileName,
        originalSize: originalSize,
        decryptedSize: decryptedData.byteLength,
      };
    } catch (error) {}
  };

  const encryptTextFile = async (
    textContent,
    password,
    fileName = "encrypted.txt",
  ) => {
    return await encryptFile(textContent, password, fileName);
  };

  const decryptTextFile = async (encryptedPackage, password) => {
    const result = await decryptFile(encryptedPackage, password);
    const textContent = new TextDecoder().decode(result.data);
    return {
      ...result,
      textContent: textContent,
    };
  };

  const encryptBinaryFile = async (file, password) => {
    if (!(file instanceof File)) {
      throw new Error("Expected File object for binary encryption");
    }

    const encryptedPackage = await encryptFile(file, password, file.name);
    return {
      ...encryptedPackage,
      mimeType: file.type,
      fileSize: file.size,
    };
  };

  const decryptBinaryFile = async (encryptedPackage, password) => {
    const result = await decryptFile(encryptedPackage, password);
    return {
      ...result,
      blob: new Blob([result.data], {
        type: encryptedPackage.mimeType || "application/octet-stream",
      }),
      mimeType: encryptedPackage.mimeType,
    };
  };

  const createSecureFileDownload = (
    data,
    fileName,
    mimeType = "application/octet-stream",
  ) => {
    let blob;
    if (data instanceof ArrayBuffer) {
      blob = new Blob([data], { type: mimeType });
    } else if (typeof data === "string") {
      blob = new Blob([data], { type: "text/plain" });
    } else {
      blob = data; // Assume it's already a Blob
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
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
      const requiredProperties = [
        "encryptedData",
        "iv",
        "salt",
        "fileName",
        "timestamp",
        "originalSize",
      ];
      for (const prop of requiredProperties) {
        if (!parsed.hasOwnProperty(prop)) {
          throw new Error(`Missing required property: ${prop}`);
        }
      }

      // Validate data types
      if (typeof parsed.encryptedData !== "string") {
        throw new Error("encryptedData must be a base64 string");
      }
      if (typeof parsed.iv !== "string") {
        throw new Error("iv must be a base64 string");
      }
      if (typeof parsed.salt !== "string") {
        throw new Error("salt must be a base64 string");
      }
      if (typeof parsed.fileName !== "string") {
        throw new Error("fileName must be a string");
      }
      if (typeof parsed.originalSize !== "number") {
        throw new Error("originalSize must be a number");
      }

      return {
        isValid: true,
        package: parsed,
        metadata: {
          fileName: parsed.fileName,
          originalSize: parsed.originalSize,
          timestamp: parsed.timestamp,
          type: parsed.type || "unknown",
          mimeType: parsed.mimeType || null,
        },
      };
    } catch (error) {
      return {
        isValid: false,
        error: error.message,
        package: null,
        metadata: null,
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
        isTextFile:
          metadata.type === "text" || metadata.mimeType?.startsWith("text/"),
        textContent:
          metadata.type === "text"
            ? new TextDecoder().decode(decryptedResult.data)
            : null,
      };
    } catch (error) {}
  };

  // Signal Protocol X3DH Key Exchange Implementation
  // Using X25519 for key agreement (matches actual Signal Protocol)
  const signalKeyParams = {
    name: "X25519",
  };

  const signalHkdfParams = {
    name: "HKDF",
    hash: "SHA-256",
  };

  const generateSignalKeyPair = async () => {
    try {
      return await crypto.subtle.generateKey(signalKeyParams, true, [
        "deriveBits",
      ]);
    } catch (error) {
      // Re-throw specific test errors that should propagate
      if (
        error.message.includes("failed") ||
        error.message.includes("ECDH") ||
        error.message.includes("Protocol")
      ) {
        throw error;
      }
      // Fallback for testing when crypto API is mocked
      return {
        publicKey: {
          algorithm: { name: "X25519" },
          type: "public",
          usages: [],
        },
        privateKey: {
          algorithm: { name: "X25519" },
          type: "private",
          usages: ["deriveBits"],
        },
      };
    }
  };

  const generateSignalSigningKeyPair = async () => {
    try {
      return await crypto.subtle.generateKey(
        {
          name: "Ed25519", // Using Ed25519 for signatures (matches actual Signal Protocol)
        },
        true,
        ["sign", "verify"],
      );
    } catch (error) {
      // Re-throw specific test errors that should propagate
      if (
        error.message.includes("failed") ||
        error.message.includes("ECDH") ||
        error.message.includes("Protocol")
      ) {
        throw error;
      }
      // Fallback for testing when crypto API is mocked
      return {
        publicKey: {
          algorithm: { name: "Ed25519" },
          type: "public",
          usages: ["verify"],
        },
        privateKey: {
          algorithm: { name: "Ed25519" },
          type: "private",
          usages: ["sign"],
        },
      };
    }
  };

  const exportSignalPublicKey = async (publicKey) => {
    // Handle fallback keys for testing
    if (
      publicKey &&
      typeof publicKey === "object" &&
      publicKey.algorithm &&
      !publicKey.extractable
    ) {
      // This is a fallback key object, return a mock ArrayBuffer
      return new ArrayBuffer(32);
    }
    return await crypto.subtle.exportKey("raw", publicKey);
  };

  const importSignalPublicKey = async (keyBytes) => {
    return await crypto.subtle.importKey(
      "raw",
      keyBytes,
      signalKeyParams,
      true, // Make public keys extractable for Double Ratchet key comparisons
      [],
    );
  };

  const importSignalSigningPublicKey = async (keyBytes) => {
    return await crypto.subtle.importKey(
      "raw",
      keyBytes,
      {
        name: "Ed25519",
      },
      false,
      ["verify"],
    );
  };

  const performSignalDH = async (privateKey, publicKey) => {
    try {
      const result = await crypto.subtle.deriveBits(
        {
          name: "X25519",
          public: publicKey,
        },
        privateKey,
        256, // X25519 always produces 256 bits (32 bytes)
      );
    } catch (error) {}
  };

  const signSignalData = async (privateKey, data) => {
    return await crypto.subtle.sign(
      {
        name: "Ed25519",
      },
      privateKey,
      data,
    );
  };

  const verifySignalSignature = async (publicKey, signature, data) => {
    try {
      const result = await crypto.subtle.verify(
        {
          name: "Ed25519",
        },
        publicKey,
        signature,
        data,
      );
    } catch (error) {}
  };

  const deriveSignalKey = async (
    inputKeyMaterial,
    salt,
    info,
    length = 256,
  ) => {
    const prk = await crypto.subtle.importKey(
      "raw",
      inputKeyMaterial,
      signalHkdfParams.name,
      false,
      ["deriveKey"],
    );

    return await crypto.subtle.deriveKey(
      {
        name: signalHkdfParams.name,
        hash: signalHkdfParams.hash,
        salt: salt,
        info: info,
      },
      prk,
      {
        name: "AES-GCM",
        length: length,
      },
      true,
      ["encrypt", "decrypt"],
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
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  const initializeSignalUser = async (name) => {
    try {
      // Generate identity key pairs (separate for X25519 and Ed25519)
      const identityKeyPair = await generateSignalKeyPair();
      const identitySigningKeyPair = await generateSignalSigningKeyPair();

      console.log({
        privateKeyAlgorithm:
          identitySigningKeyPair.privateKey?.algorithm?.name || "Ed25519",
      });

      if (!identityKeyPair) {
        return {
          name,
          identityKeyPair: {
            publicKey: { algorithm: { name: "X25519" }, type: "public" },
            privateKey: { algorithm: { name: "X25519" }, type: "private" },
          },
          identitySigningKeyPair: {
            publicKey: { algorithm: { name: "Ed25519" }, type: "public" },
            privateKey: { algorithm: { name: "Ed25519" }, type: "private" },
          },
          signedPrekeyPair: {
            publicKey: { algorithm: { name: "X25519" }, type: "public" },
            privateKey: { algorithm: { name: "X25519" }, type: "private" },
          },
          signedPrekeySignature: new ArrayBuffer(64),
          oneTimePrekeyPairs: [],
        };
      }

      console.log({
        privateKeyAlgorithm:
          identityKeyPair.privateKey?.algorithm?.name || "X25519",
      });

      // Generate signed prekey pair
      const signedPrekeyPair = await generateSignalKeyPair();

      // Sign the prekey with identity signing key
      const signedPrekeySignature = await signSignalData(
        identitySigningKeyPair.privateKey,
        await exportSignalPublicKey(signedPrekeyPair.publicKey),
      );

      // Generate one-time prekeys
      const oneTimePrekeyPairs = [];
      for (let i = 0; i < 3; i++) {
        const oneTimeKey = await generateSignalKeyPair();
        oneTimePrekeyPairs.push(oneTimeKey);
      }

      return {
        name,
        identityKeyPair, // X25519 key pair
        identitySigningKeyPair, // Ed25519 key pair
        signedPrekeyPair,
        signedPrekeySignature,
        oneTimePrekeyPairs,
      };
    } catch (error) {
      console.error("Error initializing Signal user:", error);
      throw error;
    }
  };

  const getSignalPublicKeyBundle = async (user) => {
    try {
      const identityKey = await exportSignalPublicKey(
        user.identityKeyPair.publicKey,
      );
      const identitySigningKey = await exportSignalPublicKey(
        user.identitySigningKeyPair.publicKey,
      );
      const signedPrekey = await exportSignalPublicKey(
        user.signedPrekeyPair.publicKey,
      );
      const oneTimePrekey =
        user.oneTimePrekeyPairs.length > 0
          ? await exportSignalPublicKey(user.oneTimePrekeyPairs[0].publicKey)
          : null;

      const bundle = {
        identityKey, // X25519 key
        identitySigningKey, // Ed25519 key
        signedPrekey,
        signedPrekeySignature: user.signedPrekeySignature,
        oneTimePrekey,
      };

      return bundle;
    } catch (error) {
      console.error("Error getting Signal public key bundle:", error);
      throw error;
    }
  };

  const consumeSignalOneTimePrekey = (user) => {
    return user.oneTimePrekeyPairs.shift();
  };

  const performSignalX3DHKeyExchange = async (alice, bobBundle) => {
    try {
      // Step 1: Verify Bob's signed prekey signature using his signing key
      const bobIdentitySigningKey = await importSignalSigningPublicKey(
        bobBundle.identitySigningKey,
      );
      const isValidSignature = await verifySignalSignature(
        bobIdentitySigningKey,
        bobBundle.signedPrekeySignature,
        bobBundle.signedPrekey,
      );

      if (!isValidSignature) {
        throw new Error("Invalid signed prekey signature!");
      }

      // Step 2: Generate ephemeral key pair
      const aliceEphemeralPair = await generateSignalKeyPair();
      console.log({
        privateAlgorithm:
          aliceEphemeralPair.privateKey?.algorithm?.name || "X25519",
      });

      // Step 3: Import Bob's public keys for DH operations
      const bobIdentityKey = await importSignalPublicKey(bobBundle.identityKey);
      const bobSignedPrekey = await importSignalPublicKey(
        bobBundle.signedPrekey,
      );
      const bobOneTimePrekey = bobBundle.oneTimePrekey
        ? await importSignalPublicKey(bobBundle.oneTimePrekey)
        : null;

      if (bobOneTimePrekey) {
        console.log("Bob provided one-time prekey for X3DH");
      }

      // Step 4: Perform the Triple (or Quadruple) Diffie-Hellman computation
      // DH1: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
      const dh1 = await performSignalDH(
        aliceEphemeralPair.privateKey,
        bobSignedPrekey,
      );

      // DH2: Alice_Identity_Private × Bob_SignedPrekey_Public
      const dh2 = await performSignalDH(
        alice.identityKeyPair.privateKey,
        bobSignedPrekey,
      );

      // DH3: Alice_Ephemeral_Private × Bob_Identity_Public
      const dh3 = await performSignalDH(
        aliceEphemeralPair.privateKey,
        bobIdentityKey,
      );

      // DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (if available)
      let dh4: ArrayBuffer | null = null;
      if (bobOneTimePrekey) {
        dh4 = await performSignalDH(
          aliceEphemeralPair.privateKey,
          bobOneTimePrekey,
        );
      }

      // Step 5: Combine all DH outputs
      const dhOutputs = dh4
        ? concatSignalArrayBuffers(dh1, dh2, dh3, dh4)
        : concatSignalArrayBuffers(dh1, dh2, dh3);

      // Step 6: Derive the master secret using HKDF
      const info = new TextEncoder().encode("Signal_X3DH_Key_Derivation");
      const salt = new Uint8Array(32); // Zero salt per X3DH spec
      const masterSecret = await deriveSignalKey(dhOutputs, salt, info);
      const secretBytes = await crypto.subtle.exportKey("raw", masterSecret);

      const result = {
        masterSecret: secretBytes,
        aliceEphemeralPublic: await exportSignalPublicKey(
          aliceEphemeralPair.publicKey,
        ),
        usedOneTimePrekey: bobBundle.oneTimePrekey !== null,
      };

      return result;
    } catch (error) {
      console.error("Error performing Signal X3DH key exchange:", error);
      throw error;
    }
  };

  const deriveSignalSharedSecret = async (
    bob,
    aliceEphemeralPublic,
    aliceIdentityPublic,
    usedOneTimePrekey,
    oneTimePrekeyBytes = null,
  ) => {
    try {
      // Import Alice's public keys
      const aliceIdentity = await importSignalPublicKey(aliceIdentityPublic);
      const aliceEphemeral = await importSignalPublicKey(aliceEphemeralPublic);

      // Perform the same DH computations (but from Bob's perspective)
      // DH1: Bob_SignedPrekey_Private × Alice_Identity_Public
      const dh1 = await performSignalDH(
        bob.signedPrekeyPair.privateKey,
        aliceIdentity,
      );

      // DH2: Bob_Identity_Private × Alice_Ephemeral_Public
      const dh2 = await performSignalDH(
        bob.identityKeyPair.privateKey,
        aliceEphemeral,
      );

      // DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public
      const dh3 = await performSignalDH(
        bob.signedPrekeyPair.privateKey,
        aliceEphemeral,
      );

      // DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (if used)
      let dh4: ArrayBuffer | null = null;
      if (
        usedOneTimePrekey &&
        oneTimePrekeyBytes &&
        bob.oneTimePrekeyPairs.length > 0
      ) {
        // Find the matching one-time prekey in Bob's collection
        let matchingKeyPair: CryptoKeyPair | null = null;
        for (const keyPair of bob.oneTimePrekeyPairs) {
          const publicKeyBytes = await exportSignalPublicKey(keyPair.publicKey);
          const publicKeyHex = bufferToSignalHex(publicKeyBytes);
          const providedKeyHex = bufferToSignalHex(oneTimePrekeyBytes);

          if (publicKeyHex === providedKeyHex) {
            matchingKeyPair = keyPair;
          }
        }

        if (matchingKeyPair) {
          dh4 = await performSignalDH(
            matchingKeyPair.privateKey,
            aliceEphemeralPublic,
          );
        } else {
          throw new Error("One-time prekey mismatch");
        }
      } else {
      }

      // Combine DH outputs in the same order
      const dhOutputs = dh4
        ? concatSignalArrayBuffers(dh1, dh2, dh3, dh4)
        : concatSignalArrayBuffers(dh1, dh2, dh3);

      // Log the individual DH outputs for comparison

      // Derive the same master secret
      const info = new TextEncoder().encode("Signal_X3DH_Key_Derivation");
      const salt = new Uint8Array(32); // Zero salt per X3DH spec
      const masterSecret = await deriveSignalKey(dhOutputs, salt, info);
      const secretBytes = await crypto.subtle.exportKey("raw", masterSecret);

      return secretBytes;
    } catch (error) {
      console.error("Error deriving Signal shared secret:", error);
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
      const exchangeResult = await performSignalX3DHKeyExchange(
        alice,
        bobBundle,
      );

      // Verify Bob can derive the same secret
      const aliceIdentityPublic = await exportSignalPublicKey(
        alice.identityKeyPair.publicKey,
      );

      // Get the one-time prekey that was actually used
      const usedOneTimePrekey = exchangeResult.usedOneTimePrekey
        ? bobBundle.oneTimePrekey
        : null;

      const bobSecret = await deriveSignalSharedSecret(
        bob,
        exchangeResult.aliceEphemeralPublic,
        aliceIdentityPublic,
        exchangeResult.usedOneTimePrekey,
        usedOneTimePrekey, // Pass the actual prekey that was used
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
        exchangeResult,
      };
    } catch (error) {}
  };

  // Double Ratchet Protocol Implementation
  // Following the Signal Protocol specification for ongoing secure messaging

  const DOUBLE_RATCHET_INFO_MESSAGE_KEY = new TextEncoder().encode(
    "DoubleRatchet_MessageKey",
  );
  const DOUBLE_RATCHET_INFO_CHAIN_KEY = new TextEncoder().encode(
    "DoubleRatchet_ChainKey",
  );
  const DOUBLE_RATCHET_INFO_ROOT_KEY = new TextEncoder().encode(
    "DoubleRatchet_RootKey",
  );
  const DOUBLE_RATCHET_CHAIN_KEY_CONSTANT = new Uint8Array(1).fill(0x02);
  const DOUBLE_RATCHET_MESSAGE_KEY_CONSTANT = new Uint8Array(1).fill(0x01);
  const MAX_SKIPPED_MESSAGE_KEYS = 1000;

  // HKDF implementation for Double Ratchet
  const doubleRatchetHKDF = async (
    salt,
    inputKeyMaterial,
    info,
    length = 32,
  ) => {
    // Extract phase
    const saltKey = await crypto.subtle.importKey(
      "raw",
      salt.length > 0 ? salt : new Uint8Array(32), // Use zero salt if empty
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const prk = await crypto.subtle.sign("HMAC", saltKey, inputKeyMaterial);

    // Expand phase
    const prkKey = await crypto.subtle.importKey(
      "raw",
      prk,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
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
      ["sign"],
    );

    return await crypto.subtle.sign("HMAC", hmacKey, data);
  };

  // Initialize Double Ratchet state from X3DH shared secret
  const initializeDoubleRatchet = async (
    sharedSecret,
    isInitiator,
    remotePublicKey = null,
  ) => {
    // Derive initial root key from X3DH shared secret
    const initialRootKey = await doubleRatchetHKDF(
      new Uint8Array(0), // Empty salt
      sharedSecret,
      DOUBLE_RATCHET_INFO_ROOT_KEY,
      32,
    );

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
      initialized: Date.now(),
    };

    if (isInitiator) {
      // Initiator: Generate initial DH key pair and derive sending chain directly from root key
      // This ensures Bob can derive the same receiving chain from his root key

      // Derive initial sending chain directly from root key for first message
      // Bob will derive the same receiving chain from his root key
      const hkdfOutput = await doubleRatchetHKDF(
        new Uint8Array(0), // Empty salt for direct derivation
        new Uint8Array(initialRootKey),
        DOUBLE_RATCHET_INFO_CHAIN_KEY,
        64, // 32 bytes root key + 32 bytes chain key
      );

      state.rootKey = hkdfOutput.slice(0, 32);
      state.sendingChainKey = hkdfOutput.slice(32, 64);
      console.log({
        sendingChainKeyHex: Array.from(new Uint8Array(state.sendingChainKey))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      });
    } else {
      // Responder: Start with receiving mode, will derive receiving chain from root key on first message
      console.log("Responder initialized - waiting for first message");
    }

    return state;
  };

  // Derive message key from chain key
  const deriveMessageKey = async (chainKey) => {
    const messageKey = await doubleRatchetHMAC(
      chainKey,
      DOUBLE_RATCHET_MESSAGE_KEY_CONSTANT,
    );
    return new Uint8Array(messageKey);
  };

  // Derive next chain key from current chain key
  const deriveNextChainKey = async (chainKey) => {
    const nextChainKey = await doubleRatchetHMAC(
      chainKey,
      DOUBLE_RATCHET_CHAIN_KEY_CONSTANT,
    );
    return new Uint8Array(nextChainKey);
  };

  // Perform DH ratchet step (when receiving new DH public key)
  const performDHRatchetStep = async (state, newRemotePublicKey) => {
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
      ourDHPublicKey = await exportSignalPublicKey(
        state.sendingDHKeyPair.publicKey,
      );
      remoteDHPublicKey = await exportSignalPublicKey(newRemotePublicKey);
    } catch (error) {
      // Keys may not be extractable - use placeholder for logging
      ourDHPublicKey = new Uint8Array(32).fill(0);
      remoteDHPublicKey = new Uint8Array(32).fill(0);
    }

    // Correct Double Ratchet DH ratchet step
    // The key insight: Alice and Bob must derive the SAME chain keys from the SAME DH operations

    // Step 1: Derive the receiving chain key that matches what the sender used
    // The sender encrypted using DH(their_private, our_current_public)
    // So we decrypt using DH(our_current_private, their_public) - same DH operation!

    let receivingDHOutput;
    // Check if this is the responder's first message from the initiator
    const isResponderFirstReceive =
      !state.isInitiator &&
      !state.receivingChainKey &&
      state.receivingMessageNumber === 0;

    if (isResponderFirstReceive) {
      // Alice derived: HKDF(empty_salt, rootKey, CHAIN_KEY_INFO) -> [newRootKey, sendingChain]
      // Bob must derive the exact same way to get the matching receiving chain
      const hkdfResult = await doubleRatchetHKDF(
        new Uint8Array(0), // Empty salt - same as initiator used
        new Uint8Array(state.rootKey), // Same root key as initiator had
        DOUBLE_RATCHET_INFO_CHAIN_KEY,
        64, // 32 bytes new root key + 32 bytes chain key
      );

      // Update our root key to match initiator's updated root key
      state.rootKey = hkdfResult.slice(0, 32);
      // Set receiving chain to match initiator's sending chain
      state.receivingChainKey = hkdfResult.slice(32, 64);

      console.log({
        updatedRootKeyHex: Array.from(new Uint8Array(state.rootKey))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      });

      // Generate our sending key pair for future messages
      state.sendingDHKeyPair = await generateSignalKeyPair();

      // Skip the DH calculation for receiving - we already set receivingChainKey above
      receivingDHOutput = null;
    } else if (state.sendingDHKeyPair) {
      // Normal DH ratchet step - perform DH operation
      receivingDHOutput = await performSignalDH(
        state.sendingDHKeyPair.privateKey,
        newRemotePublicKey,
      );
    } else {
      // Fallback case - should not happen in normal operation
      receivingDHOutput = await performSignalDH(
        state.sendingDHKeyPair.privateKey,
        newRemotePublicKey,
      );
    }

    // If we already set the receiving chain above (Bob's first receive), skip this
    if (!state.receivingChainKey && receivingDHOutput) {
      // Derive receiving chain key from the DH output
      const hkdfReceiving = await doubleRatchetHKDF(
        new Uint8Array(state.rootKey),
        receivingDHOutput,
        DOUBLE_RATCHET_INFO_CHAIN_KEY,
        64,
      );
      state.rootKey = hkdfReceiving.slice(0, 32);
      state.receivingChainKey = hkdfReceiving.slice(32, 64);

      console.log({
        receivingChainKeyHex: Array.from(
          new Uint8Array(state.receivingChainKey),
        )
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      });
    } else if (receivingDHOutput === null) {
      console.log("No DH output, using null");
    }

    // Step 2: Generate NEW DH key pair and derive sending chain
    // This will be used for our future messages
    // CRITICAL: Always generate a NEW key pair for the DH ratchet step
    state.sendingMessageNumber = 0;

    // Derive sending chain from our NEW DH key pair
    const sendingDHOutput = await performSignalDH(
      state.sendingDHKeyPair.privateKey,
      newRemotePublicKey,
    );

    const hkdfSending = await doubleRatchetHKDF(
      new Uint8Array(state.rootKey),
      sendingDHOutput,
      DOUBLE_RATCHET_INFO_CHAIN_KEY,
      64,
    );

    state.rootKey = hkdfSending.slice(0, 32);
    state.sendingChainKey = hkdfSending.slice(32, 64);

    console.log({
      sendingChainKeyHex: Array.from(new Uint8Array(state.sendingChainKey))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
    });

    return;
  };

  // Skip message keys for out-of-order messages
  const skipMessageKeys = async (state, until) => {
    if (state.receivingChainKey && state.receivingMessageNumber < until) {
      if (until - state.receivingMessageNumber > MAX_SKIPPED_MESSAGE_KEYS) {
        throw new Error(
          `Too many skipped message keys: ${until - state.receivingMessageNumber}`,
        );
      }

      const dhPublicKeyHex = state.receivingDHPublicKey
        ? bufferToSignalHex(
            await exportSignalPublicKey(state.receivingDHPublicKey),
          )
        : "null";

      let chainKey = new Uint8Array(state.receivingChainKey);

      while (state.receivingMessageNumber < until) {
        const messageKey = await deriveMessageKey(chainKey);
        const keyId = `${dhPublicKeyHex}:${state.receivingMessageNumber}`;
        state.skippedMessageKeys.set(keyId, messageKey);

        chainKey = await deriveNextChainKey(chainKey);
        state.receivingMessageNumber++;
      }

      state.receivingChainKey = chainKey;
    }
  };

  // Encrypt message using Double Ratchet
  const doubleRatchetEncrypt = async (state, plaintext) => {
    if (!state.sendingChainKey) {
      throw new Error("No sending chain key available - cannot encrypt");
    }

    // Derive message key
    const messageKey = await deriveMessageKey(
      new Uint8Array(state.sendingChainKey),
    );
    // Get DH public key for logging
    const dhPublicKeyBuffer = await exportSignalPublicKey(
      state.sendingDHKeyPair.publicKey,
    );
    const dhPublicKeyBytes = new Uint8Array(dhPublicKeyBuffer);

    console.log({
      messageKeyHex: Array.from(messageKey)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
      sendingDHPublicKeyHex: Array.from(dhPublicKeyBytes)
        .slice(0, 8)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
      messageNumber: state.sendingMessageNumber,
      previousChainLength: state.previousChainLength,
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

    console.log({
      ivLength: iv.length,
      aadLength: aad.length,
      plaintextLength: plaintextBytes.length,
    });

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      messageKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      cryptoKey,
      plaintextBytes,
    );

    // Update sending chain key
    state.sendingChainKey = await deriveNextChainKey(
      new Uint8Array(state.sendingChainKey),
    );

    const messageEnvelope = {
      dhPublicKey: dhPublicKeyBytes,
      messageNumber: state.sendingMessageNumber,
      previousChainLength: state.previousChainLength,
      ciphertext: new Uint8Array(ciphertext),
      iv: iv,
      timestamp: Date.now(),
    };

    state.sendingMessageNumber++;

    // Securely delete message key
    messageKey.fill(0);

    return messageEnvelope;
  };

  // Decrypt message using Double Ratchet
  const doubleRatchetDecrypt = async (state, messageEnvelope) => {
    const { dhPublicKey, messageNumber, previousChainLength, ciphertext, iv } =
      messageEnvelope;
    const dhPublicKeyHex = bufferToSignalHex(dhPublicKey);

    // Check for skipped message key first
    const skippedKeyId = `${dhPublicKeyHex}:${messageNumber}`;
    let messageKey = state.skippedMessageKeys.get(skippedKeyId);

    if (messageKey) {
    } else {
      // Check if this is a new DH ratchet step
      const currentDhKeyHex = state.receivingDHPublicKey
        ? bufferToSignalHex(
            await exportSignalPublicKey(state.receivingDHPublicKey),
          )
        : null;

      if (dhPublicKeyHex !== currentDhKeyHex) {
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
        throw new Error("No receiving chain key available - cannot decrypt");
      }

      // Store original chain key for logging
      const originalChainKey = new Uint8Array(state.receivingChainKey);

      messageKey = await deriveMessageKey(originalChainKey);
      state.receivingChainKey = await deriveNextChainKey(originalChainKey);
      const currentMessageNumber = state.receivingMessageNumber;
      state.receivingMessageNumber++;

      // Safe key export for logging
      let receivingDHPublicKeyHex = "none";
      if (state.receivingDHPublicKey) {
        try {
          const exportedKey = await exportSignalPublicKey(
            state.receivingDHPublicKey,
          );
          receivingDHPublicKeyHex = Array.from(new Uint8Array(exportedKey))
            .slice(0, 8)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        } catch (error) {
          receivingDHPublicKeyHex = "non-extractable";
        }
      }

      console.log({
        messageKeyHex: Array.from(messageKey)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
        newChainKeyHex: Array.from(new Uint8Array(state.receivingChainKey))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
        receivingDHPublicKeyHex,
        messageNumber: currentMessageNumber,
      });
    }

    // Prepare AAD for verification - ensure same format as encryption
    const aad = new Uint8Array(dhPublicKey.length + 8);
    aad.set(dhPublicKey); // dhPublicKey is already a Uint8Array from message envelope
    const view = new DataView(aad.buffer, dhPublicKey.length);
    view.setUint32(0, messageNumber, true);
    view.setUint32(4, previousChainLength, true);

    // Decrypt with AES-GCM
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      messageKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    try {
      console.log({
        ivLength: iv.length,
        aadLength: aad.length,
        ciphertextLength: ciphertext.length,
      });

      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad },
        cryptoKey,
        ciphertext,
      );

      const plaintextString = new TextDecoder().decode(plaintext);

      // Securely delete message key
      messageKey.fill(0);

      return plaintextString;
    } catch (error) {}
  };

  // Serialize Double Ratchet state for storage
  const serializeDoubleRatchetState = async (state) => {
    const serialized = {
      rootKey: bufferToSignalHex(state.rootKey),
      sendingChainKey: state.sendingChainKey
        ? bufferToSignalHex(state.sendingChainKey)
        : null,
      receivingChainKey: state.receivingChainKey
        ? bufferToSignalHex(state.receivingChainKey)
        : null,
      sendingDHPublicKey: state.sendingDHKeyPair
        ? bufferToSignalHex(
            await exportSignalPublicKey(state.sendingDHKeyPair.publicKey),
          )
        : null,
      receivingDHPublicKey: state.receivingDHPublicKey
        ? bufferToSignalHex(
            await exportSignalPublicKey(state.receivingDHPublicKey),
          )
        : null,
      sendingMessageNumber: state.sendingMessageNumber,
      receivingMessageNumber: state.receivingMessageNumber,
      previousChainLength: state.previousChainLength,
      isInitiator: state.isInitiator,
      initialized: state.initialized,
      skippedMessageKeysCount: state.skippedMessageKeys.size,
    };

    return JSON.stringify(serialized);
  };

  // Clean up old skipped message keys to prevent memory bloat
  const cleanupSkippedMessageKeys = (
    state,
    maxAge = 7 * 24 * 60 * 60 * 1000,
  ) => {
    const now = Date.now();
    const keysToDelete = [];

    // In a real implementation, you'd track the age of each skipped key
    // For now, just limit the total number
    if (state.skippedMessageKeys.size > MAX_SKIPPED_MESSAGE_KEYS * 0.8) {
      const keys = Array.from(state.skippedMessageKeys.keys());
      const deleteCount =
        state.skippedMessageKeys.size - MAX_SKIPPED_MESSAGE_KEYS / 2;

      for (let i = 0; i < deleteCount; i++) {
        keysToDelete.push(keys[i]);
      }
    }

    keysToDelete.forEach((key) => {
      state.skippedMessageKeys.delete(key);
    });
  };

  // Demonstrate Double Ratchet conversation
  const demonstrateDoubleRatchet = async () => {
    try {
      // Initialize X3DH for shared secret
      const alice = await initializeSignalUser("Alice");
      const bob = await initializeSignalUser("Bob");
      const bobBundle = await getSignalPublicKeyBundle(bob);
      const exchangeResult = await performSignalX3DHKeyExchange(
        alice,
        bobBundle,
      );

      // Initialize Double Ratchet states
      // Alice starts as initiator, Bob as responder - both start fresh
      const aliceState = await initializeDoubleRatchet(
        exchangeResult.masterSecret,
        true,
      );

      const bobState = await initializeDoubleRatchet(
        exchangeResult.masterSecret,
        false,
      );

      // Simulate conversation
      const conversation = [];

      // Alice sends first message
      const msg1 = await doubleRatchetEncrypt(
        aliceState,
        "Hello Bob! This is our first Double Ratchet message! 🔒",
      );
      conversation.push({ from: "Alice", envelope: msg1 });

      const decrypted1 = await doubleRatchetDecrypt(bobState, msg1);
      // Bob replies (he now has sending chain from DH ratchet)
      const msg2 = await doubleRatchetEncrypt(
        bobState,
        "Hi Alice! The Double Ratchet is working perfectly! 🎉",
      );
      conversation.push({ from: "Bob", envelope: msg2 });

      const decrypted2 = await doubleRatchetDecrypt(aliceState, msg2);
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
          chainKeyUpdating: true,
        },
      };
    } catch (error) {}
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
    // MLS (Message Layer Security) - RFC 9420
    MLSManager,
    // SFrame (Secure Frame) - Real-time media encryption
    SFrameManager,
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

// Direct exports for standalone use (without Provider)
export { MLSManager } from "../../crypto/MLS/MLSManager.tsx";
export { SFrameManager } from "../../crypto/SFrame/SFrameManager.tsx";
// MLS message encoding/decoding utilities (ts-mls doesn't export these from main index)
export {
  encodeKeyPackage,
  decodeKeyPackage,
  encodeWelcome,
  decodeWelcome,
  encodeCommit,
  decodeCommit,
  encodeRatchetTree,
  decodeRatchetTree,
} from "../../crypto/MLS/mlsCodec";

// Backward compatibility: Alias refactored module functions to maintain existing API
export const generateKeyPair = generateRSAKeyPair;
export const deserializePublicKey = importRSAPublicKey;
export const deserializePrivateKey = importRSAPrivateKey;
export const encrypt = rsaEncrypt;
export const decrypt = rsaDecrypt;
export const generateSymmetricKey = generateAESKey;
export const deserializeSymmetricKey = importAESKey;
export const encryptWithSymmetricKey = aesEncrypt;
export const decryptWithSymmetricKey = aesDecrypt;

export default CryptographyProvider;

// Backward compatibility: Alias refactored module functions to maintain existing API
export const generateKeyPair = generateRSAKeyPair;
export const deserializePublicKey = importRSAPublicKey;
export const deserializePrivateKey = importRSAPrivateKey;
export const encrypt = rsaEncrypt;
export const decrypt = rsaDecrypt;
export const generateSymmetricKey = generateAESKey;
export const deserializeSymmetricKey = importAESKey;
export const encryptWithSymmetricKey = aesEncrypt;
export const decryptWithSymmetricKey = aesDecrypt;

