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
    const [salt, setSalt] = useState("");
    const [chance, setChance] = useState(new Chance(salt));

    useEffect(() => {
        const updateSates = async () => {
            const newSalt = await sha256Hash(entropy);
            setSalt(newSalt);
            setChance(new Chance(newSalt));
        };
        updateSates();
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

            return {
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
            };
        } catch (error) {
            console.error("Error generating key pair:", error);
            throw error;
        }
    };

    function setClassPropsFromJson(json, instance) {
        for (let prop in json) {
            if (json.hasOwnProperty(prop)) {
                instance[prop] = json[prop];
            }
        }
        return instance;
    }

    const deserializePublicKey = async (key) => {
        try {
            const publicKey = await crypto.subtle.importKey(
                "jwk", // Import format
                key, // The key in JWK format
                {
                    name: "RSA-OAEP", // Algorithm name
                    hash: "SHA-256", // Hash algorithm
                },
                true, // Extractable flag
                ["encrypt"], // Key usages
            );

            return setClassPropsFromJson(key, publicKey);
        } catch (error) {
            console.error("Error deserializing public key:", error);
            throw error;
        }
    };

    const deserializePrivateKey = async (key) => {
        try {
            const privateKey = await crypto.subtle.importKey(
                "jwk", // Import format
                key, // The key in JWK format
                {
                    name: "RSA-OAEP", // Algorithm name
                    hash: "SHA-256", // Hash algorithm
                },
                true, // Extractable flag
                ["decrypt"], // Key usages
            );

            return setClassPropsFromJson(key, privateKey);
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

        return key;
    };

    const deserializeSymmetricKey = async (key) => {
        const deSerializedSymmetricKey = await window.crypto.subtle.importKey(
            "jwk",
            {
                ...key,
                kty: "oct",
            },
            {
                name: "AES-GCM",
            },
            true,
            ["encrypt", "decrypt"],
        );

        return setClassPropsFromJson(key, deSerializedSymmetricKey);
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