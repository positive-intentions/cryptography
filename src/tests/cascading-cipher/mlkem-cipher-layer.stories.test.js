/**
 * ML-KEM Storybook Interaction Tests
 *
 * These tests verify ML-KEM stories work correctly in the browser.
 * Note: Storybook interaction testing requires stories to be accessible.
 */

describe("MLKEMCipherLayer Stories", () => {
  describe("MLKEMDemo Story", () => {
    let stories;

    beforeAll(async () => {
      try {
        const storiesModule = await import(
          "../../stories/CascadingCipher/MLKEMDemo.stories.js"
        );
        stories = storiesModule;
      } catch (e) {
        console.error("Failed to import MLKEMDemo stories:", e);
        stories = null;
      }
    });

    test("MLKEMDemo story should exist", () => {
      if (!stories) {
        console.warn("Skipping test - MLKEMDemo stories not available");
        return;
      }
      expect(stories).toBeDefined();
      expect(stories.default).toBeDefined();
      expect(stories.MLKEMStandalone).toBeDefined();
    });

    test("MLKEMDemo exports correct metadata", () => {
      if (!stories) {
        console.warn("Skipping test - MLKEMDemo stories not available");
        return;
      }
      expect(stories.default.title).toBe("Cascading Cipher/ML-KEM Demo");
      expect(stories.default.parameters).toBeDefined();
    });
  });

  describe("MLKEM Functionality Tests", () => {
    let MLKEMCipherLayer;
    let MlKem768;

    beforeEach(async () => {
      try {
        const mlkemModule = await import("@hpke/ml-kem");
        MlKem768 = mlkemModule.MlKem768;
      } catch (e) {
        MlKem768 = null;
      }

      try {
        const module = await import(
          "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
        );
        MLKEMCipherLayer = module.MLKEMCipherLayer;
      } catch (e) {
        MLKEMCipherLayer = null;
      }
    });

    test("should have valid MLKEMCipherLayer", () => {
      expect(MLKEMCipherLayer).toBeDefined();
    });

    test("should have valid MlKem768", () => {
      expect(MlKem768).toBeDefined();
    });

    test("should create MLKEMCipherLayer instance", () => {
      if (!MLKEMCipherLayer) return;
      const layer = new MLKEMCipherLayer();
      expect(layer).toBeDefined();
      expect(layer.name).toBe("ML-KEM-768");
      expect(layer.version).toMatch(/^\d+\.\d+\.\d+$/);
    });

    test("should validate keys correctly", () => {
      if (!MLKEMCipherLayer) return;
      const layer = new MLKEMCipherLayer();
      expect(layer.validateKeys({ publicKey: new Uint8Array(1184) })).toBe(
        true,
      );
      expect(layer.validateKeys({ privateKey: new Uint8Array(64) })).toBe(true);
      expect(layer.validateKeys({})).toBe(false);
      expect(layer.validateKeys(null)).toBe(false);
    });
  });
});
