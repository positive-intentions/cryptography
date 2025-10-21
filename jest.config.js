module.exports = {
    testEnvironment: 'jest-environment-jsdom',
    setupFilesAfterEnv: ['<rootDir>/src/setupTests.js'],
    globals: {
      crypto: true,
      'ts-jest': {
        useESM: true
      }
    },
    moduleNameMapper: {
      '\\.(css|less|scss)$': 'identity-obj-proxy',
      // MLS mock used because ts-mls is an ES module incompatible with Jest
      // Real implementation is tested in Storybook (browser environment)
      '^.*/crypto/MLS/MLSManager\\.tsx$': '<rootDir>/src/__mocks__/crypto/MLS/MLSManager.tsx',
      '^.*/crypto/SFrame/SFrameManager\\.tsx$': '<rootDir>/src/__mocks__/crypto/SFrame/SFrameManager.tsx'
      // WASM files should not be mocked - they are a key output of this repo
    },
    collectCoverage: true,
    coverageReporters: ['lcov', 'text'],
    transform: {
        "^.+\\.(ts|tsx|js|jsx)$": "babel-jest"
      },
    testPathIgnorePatterns: [
        '/node_modules/',
        '/Frontend/',
        'src/tests/mls-protocol.test.js' // Requires ts-mls ES modules
    ],
    collectCoverageFrom: [
        'src/**/*.{js,jsx,ts,tsx}',
        '!src/**/*.stories.{js,jsx,ts,tsx}',
        '!src/**/*.test.{js,jsx,ts,tsx}',
        '!src/setupTests.js',
        '!src/index.ts',
        '!src/tests/wasm-test-loader.js',
        '!src/crypto/MLS/**',
        '!src/crypto/SFrame/**'
    ],
    // Configure module handling for WASM and ES modules
    transformIgnorePatterns: [
        'node_modules/(?!(@?(?:signal_protocol_wasm|pkg|ts-mls|hpke|noble|mlkem)))',
        'Frontend/pkg/(?!.*\\.js$)'
    ],
    // Enable ES module support
    extensionsToTreatAsEsm: ['.ts', '.tsx'],
    // Increase timeout for WASM compilation tests
    testTimeout: 60000
  };