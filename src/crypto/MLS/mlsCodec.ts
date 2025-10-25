/**
 * MLS Message encoding/decoding utilities
 *
 * Since ts-mls doesn't export encode/decode functions from the main package,
 * we'll use JSON serialization with Uint8Array and BigInt conversion for transmission.
 * This works for KeyPackage, Welcome, Commit, and other MLS messages.
 */

/**
 * Convert Uint8Array and BigInt to regular array/string recursively
 */
function uint8ArrayToArray(obj: any): any {
  // Handle null explicitly (important for MLS ratchet trees)
  if (obj === null) {
    return null;
  }
  if (obj instanceof Uint8Array) {
    return { __type: 'Uint8Array', data: Array.from(obj) };
  }
  if (typeof obj === 'bigint') {
    return { __type: 'BigInt', value: obj.toString() };
  }
  if (Array.isArray(obj)) {
    return obj.map(uint8ArrayToArray);
  }
  if (typeof obj === 'object') {
    const result: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        result[key] = uint8ArrayToArray(obj[key]);
      }
    }
    return result;
  }
  return obj;
}

/**
 * Convert regular arrays back to Uint8Array and strings back to BigInt recursively
 */
function arrayToUint8Array(obj: any): any {
  // Handle null: Convert to undefined for MLS compatibility
  // ts-mls expects RatchetTree = (Node | undefined)[], not (Node | null)[]
  if (obj === null) {
    return undefined;
  }

  // Check for marked Uint8Array
  if (typeof obj === 'object' && obj.__type === 'Uint8Array') {
    return new Uint8Array(obj.data);
  }

  // Check for marked BigInt
  if (typeof obj === 'object' && obj.__type === 'BigInt') {
    return BigInt(obj.value);
  }

  if (Array.isArray(obj)) {
    return obj.map(arrayToUint8Array);
  }

  if (typeof obj === 'object') {
    // Check if this is an array-like object with sequential numeric keys
    const keys = Object.keys(obj);
    const isArrayLike = keys.length > 0 && keys.every((key, index) => key === String(index));

    if (isArrayLike) {
      // Convert object with numeric keys back to array
      console.log('🔧 [mlsCodec] Converting array-like object to array, length:', keys.length);
      return keys.map(key => arrayToUint8Array(obj[key]));
    }

    const result: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        result[key] = arrayToUint8Array(obj[key]);
      }
    }
    return result;
  }

  return obj;
}

/**
 * Encode a KeyPackage to JSON string for transmission
 */
export function encodeKeyPackage(keyPackage: any): string {
  // Convert Uint8Arrays to regular arrays so they can be JSON serialized
  const serializable = uint8ArrayToArray(keyPackage);
  return JSON.stringify(serializable);
}

/**
 * Decode JSON string back to a KeyPackage object
 */
export function decodeKeyPackage(encoded: string): any {
  const parsed = JSON.parse(encoded);
  // Convert arrays back to Uint8Arrays
  return arrayToUint8Array(parsed);
}

/**
 * Encode a Welcome message to JSON string for transmission
 */
export function encodeWelcome(welcome: any): string {
  const serializable = uint8ArrayToArray(welcome);
  return JSON.stringify(serializable);
}

/**
 * Decode JSON string back to a Welcome object
 */
export function decodeWelcome(encoded: string): any {
  const parsed = JSON.parse(encoded);
  return arrayToUint8Array(parsed);
}

/**
 * Encode a Commit message to JSON string for transmission
 */
export function encodeCommit(commit: any): string {
  const serializable = uint8ArrayToArray(commit);
  return JSON.stringify(serializable);
}

/**
 * Decode JSON string back to a Commit object
 */
export function decodeCommit(encoded: string): any {
  const parsed = JSON.parse(encoded);
  return arrayToUint8Array(parsed);
}

/**
 * Encode a RatchetTree to JSON string for transmission
 */
export function encodeRatchetTree(ratchetTree: any): string {
  const serializable = uint8ArrayToArray(ratchetTree);
  return JSON.stringify(serializable);
}

/**
 * Decode JSON string back to a RatchetTree
 */
export function decodeRatchetTree(encoded: string): any {
  const parsed = JSON.parse(encoded);

  console.log('========================================');
  console.log('🔍 [mlsCodec] AFTER JSON.PARSE:');
  console.log('  Type:', typeof parsed);
  console.log('  Is Array:', Array.isArray(parsed));
  console.log('  Length:', Array.isArray(parsed) ? parsed.length : 'not an array');
  console.log('  Element 0:', parsed[0] === null ? 'NULL' : parsed[0] === undefined ? 'UNDEFINED' : typeof parsed[0]);
  if (parsed[0] && typeof parsed[0] === 'object') {
    console.log('    - Keys:', Object.keys(parsed[0]).slice(0, 10));
    console.log('    - Has nodeType:', 'nodeType' in parsed[0]);
  }
  console.log('  Element 1:', parsed[1] === null ? 'NULL' : parsed[1] === undefined ? 'UNDEFINED' : typeof parsed[1]);
  console.log('  Element 2:', parsed[2] === null ? 'NULL' : parsed[2] === undefined ? 'UNDEFINED' : typeof parsed[2]);
  if (parsed[2] && typeof parsed[2] === 'object') {
    console.log('    - Keys:', Object.keys(parsed[2]).slice(0, 10));
    console.log('    - Has nodeType:', 'nodeType' in parsed[2]);
  }

  const result = arrayToUint8Array(parsed);

  console.log('----------------------------------------');
  console.log('🔍 [mlsCodec] AFTER ARRAY_TO_UINT8ARRAY:');
  console.log('  Type:', typeof result);
  console.log('  Is Array:', Array.isArray(result));
  console.log('  Length:', Array.isArray(result) ? result.length : 'not an array');
  console.log('  Element 0:', result[0] === null ? 'NULL' : result[0] === undefined ? 'UNDEFINED' : typeof result[0]);
  if (result[0] && typeof result[0] === 'object') {
    console.log('    - Keys:', Object.keys(result[0]).slice(0, 10));
    console.log('    - Has nodeType:', 'nodeType' in result[0]);
    console.log('    - nodeType value:', result[0].nodeType);
  }
  console.log('  Element 1:', result[1] === null ? 'NULL' : result[1] === undefined ? 'UNDEFINED' : typeof result[1]);
  console.log('  Element 2:', result[2] === null ? 'NULL' : result[2] === undefined ? 'UNDEFINED' : typeof result[2]);
  if (result[2] && typeof result[2] === 'object') {
    console.log('    - Keys:', Object.keys(result[2]).slice(0, 10));
    console.log('    - Has nodeType:', 'nodeType' in result[2]);
    console.log('    - nodeType value:', result[2].nodeType);
  }
  console.log('========================================');

  return result;
}
