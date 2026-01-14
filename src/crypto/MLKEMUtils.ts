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
  let cachedInstance: MlKem768 | null = null;
  let MlKem768Class: typeof MlKem768 | null = null;

  return {
    async getInstance(): Promise<MlKem768> {
      if (cachedInstance) return cachedInstance;
      if (!MlKem768Class) {
        const mlkemModule = await import("@hpke/ml-kem");
        MlKem768Class = mlkemModule.MlKem768;
      }
      cachedInstance = new MlKem768Class();
      return cachedInstance;
    },
    async getClass(): Promise<typeof MlKem768> {
      if (!MlKem768Class) {
        const mlkemModule = await import("@hpke/ml-kem");
        MlKem768Class = mlkemModule.MlKem768;
      }
      return MlKem768Class;
    },
    async destroy(): Promise<void> {
      cachedInstance = null;
      MlKem768Class = null;
    },
  };
};

const mlkemSingleton = createMLKEMSingleton();

/**
 * Get or create cached ML-KEM instance
 * Uses dynamic import to load @hpke/ml-kem
 * @returns Promise resolving to MlKem768 instance
 */
export function getMLKEMInstance(): Promise<MlKem768> {
  return mlkemSingleton.getInstance();
}

/**
 * Get MlKem768 class (for direct instantiation)
 * @returns Promise resolving to MlKem768 class constructor
 */
export function getMlKem768Class(): Promise<typeof MlKem768> {
  return mlkemSingleton.getClass();
}

/**
 * Destroy the ML-KEM singleton instance and clear cached resources
 * This allows freeing memory used by the singleton, including large precomputed tables.
 * After calling this, the next call to getMLKEMInstance() or getMlKem768Class() will
 * reload the module and create a new instance.
 *
 * @returns Promise that resolves when cleanup is complete
 *
 * @example
 * ```typescript
 * // Use singleton
 * const instance = await getMLKEMInstance();
 *
 * // Cleanup when done
 * await destroyMLKEMSingleton();
 *
 * // Next call will create a new instance
 * const newInstance = await getMLKEMInstance();
 * ```
 */
export async function destroyMLKEMSingleton(): Promise<void> {
  await mlkemSingleton.destroy();
}
