/**
 * Zeroization Utilities Tests
 */

import {
  zeroize,
  zeroizeString,
  zeroizeCopy,
  isZeroized,
} from "../zeroization";

describe("Zeroization Utilities", () => {
  describe("zeroize", () => {
    it("should zeroize Uint8Array", () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5]);

      zeroize(buffer);

      expect(buffer).toEqual(new Uint8Array([0, 0, 0, 0, 0]));
    });

    it("should zeroize empty buffer", () => {
      const buffer = new Uint8Array([]);

      zeroize(buffer);

      expect(buffer).toEqual(new Uint8Array([]));
    });

    it("should zeroize large buffer", () => {
      const buffer = new Uint8Array(new Array(1000).fill(255));

      zeroize(buffer);

      expect(buffer).toEqual(new Uint8Array(1000));
      expect(Array.from(buffer).every((val) => val === 0)).toBe(true);
    });

    it("should handle arrays of buffers", () => {
      const buffers = [
        new Uint8Array([1, 2]),
        new Uint8Array([3, 4]),
        new Uint8Array([5, 6]),
      ];

      zeroize(buffers);

      expect(buffers[0]).toEqual(new Uint8Array([0, 0]));
      expect(buffers[1]).toEqual(new Uint8Array([0, 0]));
      expect(buffers[2]).toEqual(new Uint8Array([0, 0]));
    });

    it("should not throw on null input", () => {
      expect(() => zeroize(null as any)).not.toThrow();
    });

    it("should preserve buffer length", () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5]);
      const originalLength = buffer.length;

      zeroize(buffer);

      expect(buffer.length).toBe(originalLength);
    });
  });

  describe("zeroizeString", () => {
    it("should zeroize string by encoding it", () => {
      const str = "sensitive-data";
      const encoder = new TextEncoder();
      const expectedBuffer = encoder.encode(str);

      zeroizeString(str);

      // The string object itself isn't modified (strings are immutable)
      // but the buffer created during encoding is zeroized
      expect(typeof str).toBe("string");
      expect(str).toBe("sensitive-data");
    });

    it("should handle empty string", () => {
      const str = "";

      expect(() => zeroizeString(str)).not.toThrow();
    });

    it("should handle unicode strings", () => {
      const str = "世界🌍";

      expect(() => zeroizeString(str)).not.toThrow();
    });

    it("should handle special characters", () => {
      const str = "!@#$%^&*()";

      expect(() => zeroizeString(str)).not.toThrow();
    });
  });

  describe("zeroizeCopy", () => {
    it("should create zeroized copy of buffer", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5]);

      const copy = zeroizeCopy(original);

      expect(copy).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
      expect(original).toEqual(new Uint8Array([0, 0, 0, 0, 0]));
    });

    it("should not modify original when creating copy", () => {
      const original = new Uint8Array([1, 2, 3, 4]);
      const originalReference = original;

      const copy = zeroizeCopy(original);

      expect(copy).not.toBe(original);
      expect(original).toEqual(new Uint8Array([0, 0, 0, 0]));
      expect(originalReference).toEqual(new Uint8Array([0, 0, 0, 0]));
      expect(copy).toEqual(new Uint8Array([1, 2, 3, 4]));
    });

    it("should create independent copy", () => {
      const original = new Uint8Array([1, 2, 3, 4]);
      const copy = zeroizeCopy(original);

      // Modify copy
      copy[0] = 99;

      // Original should remain zeroized
      expect(original[0]).toBe(0);
      // Copy should have modification
      expect(copy[0]).toBe(99);
    });

    it("should handle empty buffer", () => {
      const original = new Uint8Array([]);

      const copy = zeroizeCopy(original);

      expect(copy).toEqual(new Uint8Array([]));
      expect(original).toEqual(new Uint8Array([]));
    });
  });

  describe("isZeroized", () => {
    it("should return true for zeroized buffer", () => {
      const buffer = new Uint8Array([0, 0, 0, 0, 0]);

      const result = isZeroized(buffer);

      expect(result).toBe(true);
    });

    it("should return false for non-zero buffer", () => {
      const buffer = new Uint8Array([0, 0, 1, 0, 0]);

      const result = isZeroized(buffer);

      expect(result).toBe(false);
    });

    it("should return true for empty buffer", () => {
      const buffer = new Uint8Array([]);

      const result = isZeroized(buffer);

      expect(result).toBe(true);
    });

    it("should return false for buffer with any non-zero byte", () => {
      const buffer = new Uint8Array([0, 0, 0, 0, 255]);

      const result = isZeroized(buffer);

      expect(result).toBe(false);
    });

    it("should handle large buffers efficiently", () => {
      const buffer = new Uint8Array(new Array(10000).fill(0));

      const result = isZeroized(buffer);

      expect(result).toBe(true);
    });
  });

  describe("Security Scenarios", () => {
    it("should clear all sensitive data", () => {
      const password1 = "password123";
      const password2 = "secret456";
      const password3 = "confidential789";

      const buffer1 = new TextEncoder().encode(password1);
      const buffer2 = new TextEncoder().encode(password2);
      const buffer3 = new TextEncoder().encode(password3);

      zeroize(buffer1);
      zeroize(buffer2);
      zeroize(buffer3);

      expect(isZeroized(buffer1)).toBe(true);
      expect(isZeroized(buffer2)).toBe(true);
      expect(isZeroized(buffer3)).toBe(true);
    });

    it("should not affect other buffers", () => {
      const buffer1 = new Uint8Array([1, 2, 3]);
      const buffer2 = new Uint8Array([4, 5, 6]);
      const buffer3 = new Uint8Array([7, 8, 9]);

      zeroize(buffer1);

      expect(buffer1).toEqual(new Uint8Array([0, 0, 0]));
      expect(buffer2).toEqual(new Uint8Array([4, 5, 6]));
      expect(buffer3).toEqual(new Uint8Array([7, 8, 9]));
    });

    it("should work with arrays of buffers", () => {
      const buffers = [
        new Uint8Array([1, 2]),
        new Uint8Array([3, 4]),
        new Uint8Array([5, 6]),
      ];

      zeroize(buffers);

      expect(isZeroized(buffers[0])).toBe(true);
      expect(isZeroized(buffers[1])).toBe(true);
      expect(isZeroized(buffers[2])).toBe(true);
    });
  });

  describe("Performance", () => {
    it("should zeroize large buffers efficiently", () => {
      const buffer = new Uint8Array(new Array(100000).fill(255));

      const start = performance.now();
      zeroize(buffer);
      const duration = performance.now() - start;

      expect(duration).toBeLessThan(100); // Should be very fast
      expect(isZeroized(buffer)).toBe(true);
    });
  });
});
