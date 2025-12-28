/**
 * ML-KEM Utilities
 *
 * Exports ML-KEM functionality for use via module federation
 * Uses closure-based singleton pattern to avoid module-level state issues with module federation
 */

// Re-export MlKem768 class
export { MlKem768 } from "@hpke/ml-kem";

/**
 * Create ML-KEM singleton factory
 * Uses closure to encapsulate state, avoiding module-level variables that may not work
 * correctly with webpack module federation
 */
const createMLKEMSingleton = () => {
  let cachedInstance: any = null;
  let MlKem768Class: any = null;

  return {
    async getInstance(): Promise<any> {
      if (cachedInstance) return cachedInstance;
      if (!MlKem768Class) {
        const mlkemModule = await import("@hpke/ml-kem");
        MlKem768Class = mlkemModule.MlKem768;
      }
      cachedInstance = new MlKem768Class();
      return cachedInstance;
    },
    async getClass(): Promise<any> {
      if (!MlKem768Class) {
        const mlkemModule = await import("@hpke/ml-kem");
        MlKem768Class = mlkemModule.MlKem768;
      }
      return MlKem768Class;
    },
  };
};

const mlkemSingleton = createMLKEMSingleton();

/**
 * Get or create cached ML-KEM instance
 * Uses dynamic import to load @hpke/ml-kem
 * @returns Promise resolving to MlKem768 instance
 */
export function getMLKEMInstance(): Promise<any> {
  return mlkemSingleton.getInstance();
}

/**
 * Get MlKem768 class (for direct instantiation)
 * @returns Promise resolving to MlKem768 class constructor
 */
export function getMlKem768Class(): Promise<any> {
  return mlkemSingleton.getClass();
}
