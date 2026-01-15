/**
 * @jest-environment jsdom
 */

describe("ML-KEM Module Debug", () => {
  test("should load MLKEMCipherLayer", async () => {
    try {
      console.log("Starting MLKEMCipherLayer import...");
      const module = await import(
        "../../crypto/CascadingCipher/layers/MLKEMCipherLayer.ts"
      );
      console.log("Module loaded:", Object.keys(module));
      console.log("MLKEMCipherLayer:", module.MLKEMCipherLayer);

      expect(module).toBeDefined();
      expect(module.MLKEMCipherLayer).toBeDefined();
    } catch (error) {
      console.error("Import error:", error);
      console.error("Error message:", error.message);
      console.error("Error stack:", error.stack);
      throw error;
    }
  });

  test("should load MlKem768", async () => {
    try {
      console.log("Starting MlKem768 import...");
      const module = await import("@hpke/ml-kem");
      console.log("Module loaded:", Object.keys(module));
      console.log("MlKem768:", module.MlKem768);

      expect(module).toBeDefined();
      expect(module.MlKem768).toBeDefined();
    } catch (error) {
      console.error("Import error:", error);
      console.error("Error message:", error.message);
      console.error("Error stack:", error.stack);
      throw error;
    }
  });
});
