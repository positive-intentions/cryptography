module.exports = {
    testEnvironment: 'jest-environment-jsdom',
    setupFilesAfterEnv: ['<rootDir>/src/setupTests.js'],
    globals: {
      crypto: true
    },
    moduleNameMapper: {
      '\\.(css|less|scss)$': 'identity-obj-proxy'
      // WASM files should not be mocked - they are a key output of this repo
    },
    collectCoverage: true,
    coverageReporters: ['lcov', 'text'],
    transform: {
        "^.+\\.(ts|tsx|js|jsx)$": "babel-jest"
      },
    collectCoverageFrom: [
        'src/**/*.{js,jsx,ts,tsx}',
        '!src/**/*.stories.{js,jsx,ts,tsx}',
        '!src/**/*.test.{js,jsx,ts,tsx}',
        '!src/setupTests.js',
        '!src/index.ts',
        '!src/tests/wasm-test-loader.js'
    ],
    // Configure module handling for WASM and ES modules
    transformIgnorePatterns: [
        'node_modules/(?!(signal_protocol_wasm|pkg)/)',
        'Frontend/pkg/(?!.*\\.js$)'
    ],
    // Enable ES module support
    extensionsToTreatAsEsm: ['.ts', '.tsx'],
    globals: {
        'ts-jest': {
            useESM: true
        }
    },
    // Increase timeout for WASM compilation tests
    testTimeout: 60000
  };