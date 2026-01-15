module.exports = {
  testEnvironment: "jest-environment-jsdom",
  setupFilesAfterEnv: ["<rootDir>/src/setupTests.js"],
  globals: {
    crypto: true,
    "ts-jest": {
      useESM: true,
    },
  },
  moduleNameMapper: {
    "\\.(css|less|scss|sass)$": "identity-obj-proxy",
    // MLS mock used because ts-mls is an ES module incompatible with Jest
    // Real implementation is tested in Storybook (browser environment)
    // Match both with and without .tsx extension
    "^.*/crypto/MLS/MLSManager(\\.tsx)?$":
      "<rootDir>/src/__mocks__/crypto/MLS/MLSManager.tsx",
    "^.*/MLS/MLSManager(\\.tsx)?$":
      "<rootDir>/src/__mocks__/crypto/MLS/MLSManager.tsx",
    "^.*/crypto/SFrame/SFrameManager\\.tsx$":
      "<rootDir>/src/__mocks__/crypto/SFrame/SFrame/SFrameManager.tsx",
    // Mock @noble/hashes/scrypt.js for Jest ES module compatibility
    // Real implementation uses browser-compatible pure JavaScript
    "^@noble/hashes/scrypt\\.js$":
      "<rootDir>/src/__mocks__/@noble/hashes/scrypt.js",
  },
  collectCoverage: true,
  coverageReporters: ["lcov", "text"],
  transform: {
    "^.+\\.(ts|tsx)$": "ts-jest",
  },
  testPathIgnorePatterns: [
    "/node_modules/",
    "/Frontend/",
    "src/tests/mls-protocol.test.js", // Requires ts-mls ES modules
  ],
  collectCoverageFrom: [
    "src/**/*.{js,jsx,ts,tsx}",
    "!src/**/*.stories.{js,jsx,ts,tsx}",
    "!src/**/*.test.{js,jsx,ts,tsx}",
    "!src/setupTests.js",
    "!src/index.ts",
    "!src/tests/wasm-test-loader.js",
    // Note: MLS/SFrame real implementations are excluded from Jest coverage
    // because they use Web Crypto API and ES modules incompatible with Jest.
    // Real implementations are tested in Storybook (browser environment).
    // Jest tests use mocks from src/__mocks__/ which verify API contracts.
    "!src/crypto/MLS/**",
    "!src/crypto/SFrame/**",
    "!src/crypto/SignalProtocol/**", // Add Signal Protocol modules to exclusion
  ],
  // Configure module handling for WASM and ES modules
  transformIgnorePatterns: [
    "node_modules/(?!(@?(?:signal_protocol_wasm|pkg|ts-mls|hpke|noble|mlkem)|@noble|mlkem|@noble/hashes))",
    "Frontend/pkg/(?!.*\\.js$)",
  ],
  // Enable ES module support
  extensionsToTreatAsEsm: [".ts", ".tsx"],
  // Increase timeout for WASM compilation tests
  testTimeout: 60000,
};
