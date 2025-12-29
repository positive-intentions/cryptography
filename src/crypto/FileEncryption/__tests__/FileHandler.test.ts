/**
 * File Handler Utilities Tests
 */

import {
  createSecureFileDownload,
  parseEncryptedFilePackage,
  decryptUploadedFile,
} from "../FileHandler";
import { encryptFile } from "../PasswordEncryption";

describe("File Handler Utilities", () => {
  describe("createSecureFileDownload", () => {
    beforeEach(() => {
      // Mock document and URL for tests
      global.document = {
        createElement: jest.fn(() => ({
          href: "",
          download: "",
          click: jest.fn(),
          remove: jest.fn(),
        })),
        body: {
          appendChild: jest.fn(),
          removeChild: jest.fn(),
        },
      } as any;
      global.URL = {
        createObjectURL: jest.fn(() => "blob:test-url"),
        revokeObjectURL: jest.fn(),
      } as any;
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should create download for string data", () => {
      const data = "Hello, World!";
      const fileName = "test.txt";

      createSecureFileDownload(data, fileName, "text/plain");

      expect(global.document.createElement).toHaveBeenCalledWith("a");
      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(
        (global.document.createElement as jest.Mock).mock.results[0].value
          .click,
      ).toHaveBeenCalled();
    });

    it("should create download for ArrayBuffer data", () => {
      const data = new TextEncoder().encode("Binary data").buffer;
      const fileName = "binary.bin";

      createSecureFileDownload(data, fileName);

      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(
        (global.document.createElement as jest.Mock).mock.results[0].value
          .click,
      ).toHaveBeenCalled();
    });

    it("should create download for Blob data", () => {
      const data = new Blob(["blob content"]);
      const fileName = "blob.txt";

      createSecureFileDownload(data, fileName);

      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(
        (global.document.createElement as jest.Mock).mock.results[0].value
          .click,
      ).toHaveBeenCalled();
    });

    it("should set correct filename", () => {
      const data = "test";
      const fileName = "myfile.txt";

      createSecureFileDownload(data, fileName);

      const link = (global.document.createElement as jest.Mock).mock.results[0]
        .value;
      expect(link.download).toBe(fileName);
    });

    it("should set default MIME type", () => {
      const data = "test";
      const fileName = "test.txt";

      createSecureFileDownload(data, fileName);

      expect(global.URL.createObjectURL).toHaveBeenCalled();
    });
  });

  describe("parseEncryptedFilePackage", () => {
    it("should validate correct encrypted package", async () => {
      const password = "testPassword";
      const content = "Test content";

      const encrypted = await encryptFile(content, password, "test.txt");
      const file = new File([JSON.stringify(encrypted)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(true);
      expect(validation.package).toBeDefined();
      expect(validation.package).toEqual(encrypted);
      expect(validation.error).toBeUndefined();
    });

    it("should detect missing required property", async () => {
      const incompletePackage = {
        encryptedData: "encrypted",
        iv: "iv",
        // Missing: salt, fileName, timestamp, originalSize
      };
      const file = new File(
        [JSON.stringify(incompletePackage)],
        "incomplete.json",
      );

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(false);
      expect(validation.error).toContain("Missing required property");
      expect(validation.package).toBeNull();
    });

    it("should detect invalid data types", async () => {
      const invalidPackage = {
        encryptedData: 123, // Should be string
        iv: "iv",
        salt: "salt",
        fileName: "test.txt",
        timestamp: new Date().toISOString(),
        originalSize: 100,
      };
      const file = new File([JSON.stringify(invalidPackage)], "invalid.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(false);
      expect(validation.error).toContain("must be a base64 string");
    });

    it("should detect invalid base64", async () => {
      const invalidPackage = {
        encryptedData: "not!!!base64!!!", // Invalid base64 characters
        iv: "abc123",
        salt: "def456",
        fileName: "test.txt",
        timestamp: new Date().toISOString(),
        originalSize: 100,
      };
      const file = new File(
        [JSON.stringify(invalidPackage)],
        "invalid-base64.json",
      );

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(false);
      expect(validation.error).toBeDefined();
    });

    it("should parse file metadata", async () => {
      const password = "testPassword";
      const content = "Test content";

      const encrypted = await encryptFile(content, password, "test.txt");
      const file = new File([JSON.stringify(encrypted)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.metadata).not.toBeNull();
      expect(validation.metadata).toBeDefined();
      expect(validation.metadata?.fileName).toBe("test.txt");
      expect(validation.metadata?.originalSize).toBe(content.length);
      expect(validation.metadata?.type).toBe("unknown"); // Default when not specified
    });

    it("should parse MIME type when present", async () => {
      const binaryData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const file = new File([binaryData], "test.bin", {
        type: "application/pdf",
      });

      const encrypted = await encryptFile(file, "testPassword");
      const packageFile = new File(
        [JSON.stringify(encrypted)],
        "encrypted.json",
      );

      const validation = await parseEncryptedFilePackage(packageFile);

      expect(validation.metadata?.mimeType).toBe("application/pdf");
    });

    it("should handle invalid JSON", async () => {
      const invalidJson = "{ not valid json";
      const file = new File([invalidJson], "invalid.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(false);
      expect(validation.error).toContain("Invalid JSON format");
      expect(validation.package).toBeNull();
    });
  });

  describe("decryptUploadedFile", () => {
    it("should decrypt uploaded text file", async () => {
      const password = "testPassword";
      const content = "Hello from upload";

      const encrypted = await encryptFile(content, password, "uploaded.txt");

      const decrypted = await decryptUploadedFile(encrypted, password);

      expect(decrypted.textContent).toBe(content);
      expect(decrypted.isTextFile).toBe(true);
      expect(decrypted.metadata?.fileName).toBe("uploaded.txt");
    });

    it("should decrypt uploaded binary file", async () => {
      const password = "testPassword";
      const binaryData = new Uint8Array([0x42, 0x69, 0x6e, 0x61, 0x72, 0x79]); // "Binary"
      const file = new File([binaryData], "binary.bin", {
        type: "application/octet-stream",
      });

      const encrypted = await encryptFile(file, password);

      const decrypted = await decryptUploadedFile(encrypted, password);

      expect(decrypted.isTextFile).toBe(false);
      expect(decrypted.metadata?.type).toBe("unknown");
      expect(decrypted.data).toBeDefined();
    });

    it("should identify text files by MIME type", async () => {
      const password = "testPassword";
      const file = new File(["text content"], "text.txt", {
        type: "text/plain",
      });

      const encrypted = await encryptFile(file, password);

      const decrypted = await decryptUploadedFile(encrypted, password);

      expect(decrypted.isTextFile).toBe(true);
      expect(decrypted.textContent).toBe("text content");
    });

    it("should reject invalid packages", async () => {
      const invalidPackage = {
        encryptedData: "invalid",
        iv: "iv",
        salt: "salt",
        fileName: "test.txt",
        timestamp: new Date().toISOString(),
        originalSize: 100,
      } as any; // Type assertion for test

      await expect(
        decryptUploadedFile(invalidPackage, "password"),
      ).rejects.toThrow();
    });

    it("should fail with wrong password", async () => {
      const password = "correctPassword";
      const content = "Secret content";

      const encrypted = await encryptFile(content, password, "secret.txt");

      await expect(
        decryptUploadedFile(encrypted, "wrongPassword"),
      ).rejects.toThrow();
    });

    it("should preserve metadata through decryption", async () => {
      const password = "testPassword";
      const content = "Content with metadata";

      const encrypted = await encryptFile(content, password, "file.txt");

      const decrypted = await decryptUploadedFile(encrypted, password);

      expect(decrypted.metadata).not.toBeNull();
      expect(decrypted.metadata?.fileName).toBe("file.txt");
      expect(decrypted.metadata?.originalSize).toBe(content.length);
      expect(decrypted.metadata?.timestamp).toBeDefined();
    });
  });

  describe("File Validation Edge Cases", () => {
    it("should handle empty fileName", async () => {
      const password = "testPassword";
      const content = "Test";

      const encrypted = await encryptFile(content, password, "");
      const file = new File([JSON.stringify(encrypted)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(true);
      expect(validation.package?.fileName).toBe("");
    });

    it("should handle empty timestamp", async () => {
      const password = "testPassword";
      const content = "Test";

      const encrypted = await encryptFile(content, password, "test.txt");
      const noTimestamp = { ...encrypted, timestamp: undefined };
      const file = new File([JSON.stringify(noTimestamp)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(true);
      expect(validation.metadata?.timestamp).toBeDefined();
    });

    it("should handle zero-size files", async () => {
      const password = "testPassword";
      const content = "";

      const encrypted = await encryptFile(content, password, "empty.txt");
      const file = new File([JSON.stringify(encrypted)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(true);
      expect(validation.metadata?.originalSize).toBe(0);
    });

    it("should handle very large files", async () => {
      const password = "testPassword";
      const content = "x".repeat(1000000); // 1MB

      const encrypted = await encryptFile(content, password, "large.txt");
      const file = new File([JSON.stringify(encrypted)], "encrypted.json");

      const validation = await parseEncryptedFilePackage(file);

      expect(validation.isValid).toBe(true);
      expect(validation.metadata?.originalSize).toBe(content.length);
    });
  });
});
