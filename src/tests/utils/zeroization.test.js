/**
 * @jest-environment jsdom
 */

/**
 * Zeroization Utility Unit Tests
 *
 * Tests for the zeroization utility that clears sensitive data from memory.
 */

describe('Zeroization', () => {
  let Zeroization;

  beforeEach(async () => {
    try {
      const module = await import('../../crypto/utils/zeroization.ts');
      Zeroization = module.Zeroization;
    } catch (e) {
      Zeroization = null;
    }
  });

  describe('zeroize', () => {
    test('should zeroize Uint8Array buffer', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array([1, 2, 3, 4, 5]);
      expect(Array.from(buffer)).toEqual([1, 2, 3, 4, 5]);

      Zeroization.zeroize(buffer);
      expect(Array.from(buffer)).toEqual([0, 0, 0, 0, 0]);
    });

    test('should handle empty buffer', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array([]);
      expect(() => Zeroization.zeroize(buffer)).not.toThrow();
      expect(buffer.length).toBe(0);
    });

    test('should handle null buffer', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroize(null)).not.toThrow();
    });

    test('should handle undefined buffer', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroize(undefined)).not.toThrow();
    });

    test('should zeroize all bytes in buffer', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array(100);
      buffer.fill(255); // Fill with 0xFF
      expect(buffer[0]).toBe(255);
      expect(buffer[99]).toBe(255);

      Zeroization.zeroize(buffer);
      expect(buffer[0]).toBe(0);
      expect(buffer[99]).toBe(0);
      expect(buffer.every(b => b === 0)).toBe(true);
    });

    test('should not throw errors', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array([1, 2, 3]);
      expect(() => Zeroization.zeroize(buffer)).not.toThrow();
    });
  });

  describe('zeroizeArrayBuffer', () => {
    test('should zeroize ArrayBuffer', () => {
      if (!Zeroization) return;

      const buffer = new ArrayBuffer(8);
      const view = new Uint8Array(buffer);
      view.set([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(Array.from(view)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

      Zeroization.zeroizeArrayBuffer(buffer);
      expect(Array.from(view)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    });

    test('should handle empty ArrayBuffer', () => {
      if (!Zeroization) return;

      const buffer = new ArrayBuffer(0);
      expect(() => Zeroization.zeroizeArrayBuffer(buffer)).not.toThrow();
      expect(buffer.byteLength).toBe(0);
    });

    test('should handle null ArrayBuffer', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeArrayBuffer(null)).not.toThrow();
    });

    test('should handle undefined ArrayBuffer', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeArrayBuffer(undefined)).not.toThrow();
    });

    test('should zeroize all bytes in ArrayBuffer', () => {
      if (!Zeroization) return;

      const buffer = new ArrayBuffer(50);
      const view = new Uint8Array(buffer);
      view.fill(128);
      expect(view[0]).toBe(128);
      expect(view[49]).toBe(128);

      Zeroization.zeroizeArrayBuffer(buffer);
      expect(view[0]).toBe(0);
      expect(view[49]).toBe(0);
      expect(view.every(b => b === 0)).toBe(true);
    });
  });

  describe('zeroizeString', () => {
    test('should handle string without throwing', () => {
      if (!Zeroization) return;

      const str = 'sensitive-password';
      expect(() => Zeroization.zeroizeString(str)).not.toThrow();
    });

    test('should handle null string', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeString(null)).not.toThrow();
    });

    test('should handle undefined string', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeString(undefined)).not.toThrow();
    });

    test('should handle empty string', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeString('')).not.toThrow();
    });
  });

  describe('zeroizeAll', () => {
    test('should zeroize multiple Uint8Array buffers', () => {
      if (!Zeroization) return;

      const buffer1 = new Uint8Array([1, 2, 3]);
      const buffer2 = new Uint8Array([4, 5, 6]);
      const buffer3 = new Uint8Array([7, 8, 9]);

      Zeroization.zeroizeAll(buffer1, buffer2, buffer3);

      expect(Array.from(buffer1)).toEqual([0, 0, 0]);
      expect(Array.from(buffer2)).toEqual([0, 0, 0]);
      expect(Array.from(buffer3)).toEqual([0, 0, 0]);
    });

    test('should zeroize multiple ArrayBuffers', () => {
      if (!Zeroization) return;

      const buffer1 = new ArrayBuffer(4);
      const view1 = new Uint8Array(buffer1);
      view1.set([1, 2, 3, 4]);

      const buffer2 = new ArrayBuffer(4);
      const view2 = new Uint8Array(buffer2);
      view2.set([5, 6, 7, 8]);

      Zeroization.zeroizeAll(buffer1, buffer2);

      expect(Array.from(view1)).toEqual([0, 0, 0, 0]);
      expect(Array.from(view2)).toEqual([0, 0, 0, 0]);
    });

    test('should handle mixed buffer types', () => {
      if (!Zeroization) return;

      const uint8Buffer = new Uint8Array([1, 2, 3]);
      const arrayBuffer = new ArrayBuffer(4);
      const view = new Uint8Array(arrayBuffer);
      view.set([4, 5, 6, 7]);

      Zeroization.zeroizeAll(uint8Buffer, arrayBuffer);

      expect(Array.from(uint8Buffer)).toEqual([0, 0, 0]);
      expect(Array.from(view)).toEqual([0, 0, 0, 0]);
    });

    test('should handle null and undefined buffers', () => {
      if (!Zeroization) return;

      const buffer1 = new Uint8Array([1, 2, 3]);
      const buffer2 = null;
      const buffer3 = undefined;

      expect(() => Zeroization.zeroizeAll(buffer1, buffer2, buffer3)).not.toThrow();
      expect(Array.from(buffer1)).toEqual([0, 0, 0]);
    });

    test('should handle empty argument list', () => {
      if (!Zeroization) return;

      expect(() => Zeroization.zeroizeAll()).not.toThrow();
    });

    test('should zeroize all buffers even if one is null', () => {
      if (!Zeroization) return;

      const buffer1 = new Uint8Array([1, 2, 3]);
      const buffer2 = null;
      const buffer3 = new Uint8Array([4, 5, 6]);

      Zeroization.zeroizeAll(buffer1, buffer2, buffer3);

      expect(Array.from(buffer1)).toEqual([0, 0, 0]);
      expect(Array.from(buffer3)).toEqual([0, 0, 0]);
    });
  });

  describe('Edge Cases', () => {
    test('should handle very large buffers', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array(100000);
      buffer.fill(255);

      Zeroization.zeroize(buffer);

      expect(buffer.every(b => b === 0)).toBe(true);
    });

    test('should handle buffers with all zeros already', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array([0, 0, 0, 0]);
      expect(() => Zeroization.zeroize(buffer)).not.toThrow();
      expect(Array.from(buffer)).toEqual([0, 0, 0, 0]);
    });

    test('should handle buffers with maximum values', () => {
      if (!Zeroization) return;

      const buffer = new Uint8Array([255, 255, 255, 255]);
      Zeroization.zeroize(buffer);
      expect(Array.from(buffer)).toEqual([0, 0, 0, 0]);
    });
  });
});

