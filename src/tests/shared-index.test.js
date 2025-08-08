/**
 * Test for shared components index file to achieve 100% coverage
 */

describe('Shared Components Index', () => {
    test('exports all components correctly', () => {
        // This will import and execute the index file, covering all lines
        const exports = require('../stories/components/shared/index.js');
        
        expect(exports.CryptoDemo).toBeDefined();
        expect(exports.CodeDisplay).toBeDefined();
        expect(exports.OperationStatus).toBeDefined();
        expect(typeof exports.CryptoDemo).toBe('function');
        expect(typeof exports.CodeDisplay).toBe('function');  
        expect(typeof exports.OperationStatus).toBe('function');
    });
});