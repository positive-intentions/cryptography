/**
 * File Handling Utilities for Encryption/Decryption
 * @module FileEncryption
 */

import type {
  EncryptedFilePackage,
  DecryptedFileWithMetadata,
} from "./PasswordEncryption";

/**
 * File package validation result
 */
export interface FilePackageValidation {
  isValid: boolean;
  error?: string;
  package: EncryptedFilePackage | null;
  metadata: FileMetadata | null;
}

/**
 * File metadata
 */
export interface FileMetadata {
  fileName: string;
  originalSize: number;
  timestamp: string;
  type: string;
  mimeType: string | null;
}

/**
 * Creates a secure file download in the browser
 *
 * @param data - Data to download (string, ArrayBuffer, or Blob)
 * @param fileName - Name of the file to download
 * @param mimeType - Optional MIME type (default: "application/octet-stream")
 *
 * Creates a temporary download link, triggers it, then cleans up
 * Works in browser environments with document object
 *
 * @example
 * ```typescript
 * const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
 * createSecureFileDownload(data, "hello.txt", "text/plain");
 * ```
 */
export function createSecureFileDownload(
  data: string | ArrayBuffer | Blob,
  fileName: string,
  mimeType = "application/octet-stream",
): void {
  let blob: Blob;
  if (data instanceof ArrayBuffer) {
    blob = new Blob([data], { type: mimeType });
  } else if (typeof data === "string") {
    blob = new Blob([data], { type: "text/plain" });
  } else {
    blob = data as Blob; // Assume it's already a Blob
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Parses and validates an encrypted file package from a File object
 *
 * @param file - File object to parse (should be JSON)
 * @returns Promise resolving to validation result
 *
 * Validates required properties, data types, and format
 * Returns isValid flag and either the parsed package or error details
 *
 * @example
 * ```typescript
 * const validation = await parseEncryptedFilePackage(file);
 * if (validation.isValid) {
 *   const decrypted = await decryptFile(validation.package, password);
 * } else {
 *   console.error(validation.error);
 * }
 * ```
 */
export async function parseEncryptedFilePackage(
  file: File,
): Promise<FilePackageValidation> {
  try {
    // Read the file content
    const content = await file.text();

    // Parse as JSON
    const parsed: Record<string, unknown> = JSON.parse(content);

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
      if (!(prop in parsed)) {
        return {
          isValid: false,
          error: `Missing required property: ${prop}`,
          package: null,
          metadata: null,
        };
      }
    }

    // Validate data types
    if (typeof parsed.encryptedData !== "string") {
      return {
        isValid: false,
        error: "encryptedData must be a base64 string",
        package: null,
        metadata: null,
      };
    }

    if (typeof parsed.iv !== "string") {
      return {
        isValid: false,
        error: "iv must be a base64 string",
        package: null,
        metadata: null,
      };
    }

    if (typeof parsed.salt !== "string") {
      return {
        isValid: false,
        error: "salt must be a base64 string",
        package: null,
        metadata: null,
      };
    }

    if (typeof parsed.fileName !== "string") {
      return {
        isValid: false,
        error: "fileName must be a string",
        package: null,
        metadata: null,
      };
    }

    if (typeof parsed.originalSize !== "number") {
      return {
        isValid: false,
        error: "originalSize must be a number",
        package: null,
        metadata: null,
      };
    }

    // Parse timestamp if present
    let timestamp = parsed.timestamp || new Date().toISOString();
    if (typeof timestamp !== "string") {
      timestamp = new Date().toISOString();
    }

    // Return validated package
    const pkg = parsed as EncryptedFilePackage;
    const meta: FileMetadata = {
      fileName: pkg.fileName as string,
      originalSize: pkg.originalSize as number,
      timestamp: timestamp,
      type: (parsed.type as string | undefined) || "unknown",
      mimeType: (parsed.mimeType as string | null | undefined) || null,
    };

    return {
      isValid: true,
      package: pkg,
      metadata: meta,
    };
  } catch (error) {
    return {
      isValid: false,
      error: error instanceof Error ? error.message : "Invalid JSON format",
      package: null,
      metadata: null,
    };
  }
}

/**
 * Decrypts an uploaded encrypted file package
 *
 * @param encryptedFilePackage - Encrypted file package
 * @param password - Password for decryption
 * @returns Promise resolving to decrypted result with metadata
 * @throws Error if package is invalid, password is wrong, or data is corrupted
 *
 * First validates the package, then decrypts, then provides enhanced metadata
 * Determines if decrypted content is text based on type field or MIME type
 *
 * @example
 * ```typescript
 * try {
 *   const decrypted = await decryptUploadedFile(encryptedPackage, "myPassword");
 *   console.log(decrypted.textContent); // For text files
 *   console.log(decrypted.blob); // For binary files
 * } catch (error) {
 *   console.error("Decryption failed:", error);
 * }
 * ```
 */
export async function decryptUploadedFile(
  encryptedFilePackage: EncryptedFilePackage,
  password: string,
): Promise<DecryptedFileWithMetadata> {
  try {
    // First validate the package
    const validation = await parseEncryptedFilePackage({
      name: encryptedFilePackage.fileName || "unknown",
      text: JSON.stringify(encryptedFilePackage),
    } as File);

    if (!validation.isValid) {
      throw new Error(`Invalid encrypted file package: ${validation.error}`);
    }

    const { package: pkg, metadata } = validation;

    // Decrypt the file using password-based encryption
    const { decryptFile } = await import("./PasswordEncryption");
    const decryptedResult = await decryptFile(pkg, password);

    // Determine if it's a text file
    const isTextFile =
      metadata.type === "text" || metadata.mimeType?.startsWith("text/");

    // Return enhanced result with metadata
    return {
      ...decryptedResult,
      metadata: metadata,
      isTextFile,
      textContent: isTextFile
        ? new TextDecoder().decode(decryptedResult.data)
        : null,
    };
  } catch (error) {
    throw new Error(
      `File upload decryption failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
