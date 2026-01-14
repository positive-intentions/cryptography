/**
 * @jest-environment jsdom
 */

describe("ML-KEM Module Loading Test", () => {
  test("should import MLKEMCipherLayer with experimental VM modules", async () => {
    NODE_OPTIONS = "--experimental-vm-modules";

    try {
      const module = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      expect(module).toBeDefined();
      expect(module.MLKEMCipherLayer).toBeDefined();
      console.log("MLKEMCipherLayer imported successfully");
    } catch (error) {
      console.error("Import failed:", error);
      throw error;
    }
  });

  test("should import MlKem768 with experimental VM modules", async () => {
    NODE_OPTIONS = "--experimental-vm-modules";

    try {
      const mlkemModule = await import("@hpke/ml-kem");
      expect(mlkemModule).toBeDefined();
      expect(mlkemModule.MlKem768).toBeDefined();
      console.log("MlKem768 imported successfully");
    } catch (error) {
      console.error("Import failed:", error);
      throw error;
    }
  });
});
