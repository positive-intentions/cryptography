/**
 * Mock SFrame Manager for Jest tests
 * This mock avoids ES module import issues during testing
 */

export class SFrameManager {
  constructor() {
    this.contexts = new Map();
  }

  async createContext(contextId) {
    const mockContext = {
      contextId,
      keyId: Math.random().toString(36)
    };
    this.contexts.set(contextId, mockContext);
    return mockContext;
  }

  async encryptFrame(contextId, data) {
    return `encrypted:${data}`;
  }

  async decryptFrame(contextId, encryptedData) {
    return encryptedData.replace('encrypted:', '');
  }

  getContext(contextId) {
    return this.contexts.get(contextId);
  }
}

export default SFrameManager;
