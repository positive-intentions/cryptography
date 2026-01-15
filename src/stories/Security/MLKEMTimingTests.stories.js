/**
 * ML-KEM Timing Attack Protection Tests
 *
 * Interactive Storybook stories for testing ML-KEM timing consistency
 * in a browser environment. These tests verify that ML-KEM operations
 * have consistent timing regardless of success/failure to prevent
 * timing-based side-channel attacks.
 */

import React, { useState, useEffect } from "react";
import { MLKEMCipherLayer } from "../../crypto/CascadingCipher";
import { MlKem768 } from "@hpke/ml-kem";
import {
  ThemeProvider,
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Stack,
  Alert,
  Card,
  CardContent,
  CardHeader,
  Grid,
  LinearProgress,
  Tabs,
  Tab,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
} from "ui";

export default {
  title: "Cryptography/Security/ML-KEM Timing Tests",
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        component:
          "Timing attack protection tests for ML-KEM cipher layer. Verifies that operations have consistent timing regardless of success/failure.",
      },
    },
  },
};

/**
 * Measure timing for multiple runs
 */
const measureTiming = async (operation, runs = 50, warmupRuns = 1) => {
  // Warm-up runs to stabilize JIT compilation
  for (let i = 0; i < warmupRuns; i++) {
    try {
      const result = operation();
      if (result && typeof result.then === "function") {
        await result;
      }
    } catch (e) {
      // Ignore errors during warm-up
    }
  }

  // Actual measurement runs
  const timings = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    try {
      const result = operation();
      if (result && typeof result.then === "function") {
        await result;
      }
    } catch (e) {
      // Ignore errors, we're measuring timing
    }
    const end = performance.now();
    timings.push(end - start);
  }
  return timings;
};

/**
 * Calculate variance using median (more robust to outliers)
 */
const calculateVariance = (timings1, timings2) => {
  const sorted1 = [...timings1].sort((a, b) => a - b);
  const sorted2 = [...timings2].sort((a, b) => a - b);
  const median1 = sorted1[Math.floor(sorted1.length / 2)];
  const median2 = sorted2[Math.floor(sorted2.length / 2)];
  const variance = Math.abs(median1 - median2) / Math.max(median1, median2);
  return variance;
};

/**
 * Calculate statistics for timing data
 */
const calculateStats = (timings) => {
  const sorted = [...timings].sort((a, b) => a - b);
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
  const variance =
    timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) /
    timings.length;
  const stdDev = Math.sqrt(variance);
  const min = Math.min(...timings);
  const max = Math.max(...timings);
  const median = sorted[Math.floor(sorted.length / 2)];
  const q1 = sorted[Math.floor(sorted.length / 4)];
  const q3 = sorted[Math.floor((sorted.length * 3) / 4)];
  const coefficientOfVariation = stdDev / mean;

  return { mean, stdDev, min, max, median, q1, q3, coefficientOfVariation };
};

const MLKEMTimingTestsDemo = () => {
  const [tabValue, setTabValue] = useState(0);
  const [keyPair1, setKeyPair1] = useState(null);
  const [keyPair2, setKeyPair2] = useState(null);
  const [initializing, setInitializing] = useState(false);

  // Test 1: validateKeys timing
  const [test1Running, setTest1Running] = useState(false);
  const [test1Results, setTest1Results] = useState(null);

  // Test 2: validateKeys null vs invalid
  const [test2Running, setTest2Running] = useState(false);
  const [test2Results, setTest2Results] = useState(null);

  // Test 3: validateKeys different key types
  const [test3Running, setTest3Running] = useState(false);
  const [test3Results, setTest3Results] = useState(null);

  // Test 4: encryption timing
  const [test4Running, setTest4Running] = useState(false);
  const [test4Results, setTest4Results] = useState(null);

  // Test 5: decryption timing
  const [test5Running, setTest5Running] = useState(false);
  const [test5Results, setTest5Results] = useState(null);

  // Initialize key pairs
  useEffect(() => {
    const initKeys = async () => {
      if (keyPair1 && keyPair2) return;
      setInitializing(true);
      try {
        const kem1 = new MlKem768();
        const kem2 = new MlKem768();
        const pair1 = await kem1.generateKeyPair();
        const pair2 = await kem2.generateKeyPair();
        setKeyPair1(pair1);
        setKeyPair2(pair2);
      } catch (error) {
        console.error("Failed to initialize keys:", error);
      } finally {
        setInitializing(false);
      }
    };
    initKeys();
  }, []);

  // Test 1: validateKeys() timing for valid vs invalid keys
  const runTest1 = async () => {
    if (!keyPair1) return;
    setTest1Running(true);
    setTest1Results(null);

    try {
      const layer = new MLKEMCipherLayer();
      const validKeys = { publicKey: keyPair1.publicKey };
      const invalidKeys = {};

      const validTimings = await measureTiming(() => {
        layer.validateKeys(validKeys);
      }, 50);

      const invalidTimings = await measureTiming(() => {
        layer.validateKeys(invalidKeys);
      }, 50);

      const variance = calculateVariance(validTimings, invalidTimings);
      const validStats = calculateStats(validTimings);
      const invalidStats = calculateStats(invalidTimings);

      setTest1Results({
        variance,
        validStats,
        invalidStats,
        validTimings,
        invalidTimings,
        passed: variance < 0.75,
      });
    } catch (error) {
      setTest1Results({ error: error.message });
    } finally {
      setTest1Running(false);
    }
  };

  // Test 2: validateKeys() timing for null vs invalid keys
  const runTest2 = async () => {
    setTest2Running(true);
    setTest2Results(null);

    try {
      const layer = new MLKEMCipherLayer();
      const nullKeys = null;
      const invalidKeys = {};

      const nullTimings = await measureTiming(() => {
        layer.validateKeys(nullKeys);
      }, 50);

      const invalidTimings = await measureTiming(() => {
        layer.validateKeys(invalidKeys);
      }, 50);

      const variance = calculateVariance(nullTimings, invalidTimings);
      const nullStats = calculateStats(nullTimings);
      const invalidStats = calculateStats(invalidTimings);

      setTest2Results({
        variance,
        nullStats,
        invalidStats,
        nullTimings,
        invalidTimings,
        passed: variance < 0.75,
      });
    } catch (error) {
      setTest2Results({ error: error.message });
    } finally {
      setTest2Running(false);
    }
  };

  // Test 3: validateKeys() timing for different key types
  const runTest3 = async () => {
    setTest3Running(true);
    setTest3Results(null);

    try {
      const layer = new MLKEMCipherLayer();

      const publicKeyKeys = { publicKey: new Uint8Array(1184) };
      const privateKeyKeys = { privateKey: new Uint8Array(64) };
      const bothKeys = {
        publicKey: new Uint8Array(1184),
        privateKey: new Uint8Array(64),
      };
      const emptyKeys = {};

      const publicKeyTimings = await measureTiming(() => {
        layer.validateKeys(publicKeyKeys);
      }, 50);

      const privateKeyTimings = await measureTiming(() => {
        layer.validateKeys(privateKeyKeys);
      }, 50);

      const bothKeysTimings = await measureTiming(() => {
        layer.validateKeys(bothKeys);
      }, 50);

      const emptyKeysTimings = await measureTiming(() => {
        layer.validateKeys(emptyKeys);
      }, 50);

      const publicKeyVariance = calculateVariance(
        publicKeyTimings,
        privateKeyTimings,
      );
      const bothKeysVariance = calculateVariance(
        publicKeyTimings,
        bothKeysTimings,
      );
      const emptyVariance = calculateVariance(
        publicKeyTimings,
        emptyKeysTimings,
      );

      const publicKeyStats = calculateStats(publicKeyTimings);
      const privateKeyStats = calculateStats(privateKeyTimings);
      const bothKeysStats = calculateStats(bothKeysTimings);
      const emptyKeysStats = calculateStats(emptyKeysTimings);

      setTest3Results({
        publicKeyVariance,
        bothKeysVariance,
        emptyVariance,
        publicKeyStats,
        privateKeyStats,
        bothKeysStats,
        emptyKeysStats,
        passed:
          publicKeyVariance < 0.75 &&
          bothKeysVariance < 0.75 &&
          emptyVariance < 0.75,
      });
    } catch (error) {
      setTest3Results({ error: error.message });
    } finally {
      setTest3Running(false);
    }
  };

  // Test 4: encryption timing for valid vs invalid keys
  const runTest4 = async () => {
    if (!keyPair1) return;
    setTest4Running(true);
    setTest4Results(null);

    try {
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test message");

      const validTimings = await measureTiming(async () => {
        try {
          await layer.encrypt(plaintext, { publicKey: keyPair1.publicKey });
        } catch (e) {
          // Ignore errors
        }
      }, 20);

      const invalidTimings = await measureTiming(async () => {
        try {
          await layer.encrypt(plaintext, { publicKey: new Uint8Array(100) });
        } catch (e) {
          // Expected error
        }
      }, 20);

      const variance = calculateVariance(validTimings, invalidTimings);
      const validStats = calculateStats(validTimings);
      const invalidStats = calculateStats(invalidTimings);

      setTest4Results({
        variance,
        validStats,
        invalidStats,
        validTimings,
        invalidTimings,
        passed: variance < 0.75,
      });
    } catch (error) {
      setTest4Results({ error: error.message });
    } finally {
      setTest4Running(false);
    }
  };

  // Test 5: decryption timing for valid vs invalid keys
  const runTest5 = async () => {
    if (!keyPair1 || !keyPair2) return;
    setTest5Running(true);
    setTest5Results(null);

    try {
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode("Test message");

      // Encrypt valid data first
      const encrypted = await layer.encrypt(plaintext, {
        publicKey: keyPair1.publicKey,
      });

      const validTimings = await measureTiming(async () => {
        try {
          await layer.decrypt(encrypted, { privateKey: keyPair1.privateKey });
        } catch (e) {
          // Ignore errors
        }
      }, 20);

      const invalidTimings = await measureTiming(async () => {
        try {
          await layer.decrypt(encrypted, { privateKey: keyPair2.privateKey });
        } catch (e) {
          // Expected error - wrong key
        }
      }, 20);

      const variance = calculateVariance(validTimings, invalidTimings);
      const validStats = calculateStats(validTimings);
      const invalidStats = calculateStats(invalidTimings);

      setTest5Results({
        variance,
        validStats,
        invalidStats,
        validTimings,
        invalidTimings,
        passed: variance < 0.75,
      });
    } catch (error) {
      setTest5Results({ error: error.message });
    } finally {
      setTest5Running(false);
    }
  };

  const renderTestResults = (results, testName) => {
    if (!results) return null;

    if (results.error) {
      return (
        <Alert severity="error" sx={{ mt: 2 }}>
          Error: {results.error}
        </Alert>
      );
    }

    return (
      <Card sx={{ mt: 2 }}>
        <CardContent>
          <Stack spacing={2}>
            <Box>
              <Chip
                label={results.passed ? "PASSED" : "FAILED"}
                color={results.passed ? "success" : "error"}
                sx={{ mb: 2 }}
              />
              <Typography variant="h6" gutterBottom>
                {testName} Results
              </Typography>
            </Box>

            {results.variance !== undefined && (
              <Alert
                severity={results.passed ? "success" : "warning"}
                sx={{ mb: 2 }}
              >
                <Typography variant="body2">
                  <strong>Timing Variance:</strong>{" "}
                  {(results.variance * 100).toFixed(2)}%
                </Typography>
                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                  Threshold: &lt; 75% (JavaScript timing is variable)
                </Typography>
              </Alert>
            )}

            {results.validStats && results.invalidStats && (
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Valid Keys Timing
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Mean"
                        secondary={`${results.validStats.mean.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Median"
                        secondary={`${results.validStats.median.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Std Dev"
                        secondary={`${results.validStats.stdDev.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Min - Max"
                        secondary={`${results.validStats.min.toFixed(3)}ms - ${results.validStats.max.toFixed(3)}ms`}
                      />
                    </ListItem>
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Invalid Keys Timing
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Mean"
                        secondary={`${results.invalidStats.mean.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Median"
                        secondary={`${results.invalidStats.median.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Std Dev"
                        secondary={`${results.invalidStats.stdDev.toFixed(3)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Min - Max"
                        secondary={`${results.invalidStats.min.toFixed(3)}ms - ${results.invalidStats.max.toFixed(3)}ms`}
                      />
                    </ListItem>
                  </List>
                </Grid>
              </Grid>
            )}

            {results.publicKeyVariance !== undefined && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Variance Between Key Types
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary="Public vs Private Key"
                      secondary={`${(results.publicKeyVariance * 100).toFixed(2)}%`}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Public vs Both Keys"
                      secondary={`${(results.bothKeysVariance * 100).toFixed(2)}%`}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Public vs Empty Keys"
                      secondary={`${(results.emptyVariance * 100).toFixed(2)}%`}
                    />
                  </ListItem>
                </List>
              </Box>
            )}
          </Stack>
        </CardContent>
      </Card>
    );
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h3" gutterBottom>
        🔐 ML-KEM Timing Attack Protection Tests
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Interactive timing tests for ML-KEM cipher layer. These tests verify
        that cryptographic operations have consistent timing regardless of
        success/failure to prevent timing-based side-channel attacks.
      </Typography>

      {initializing && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            Initializing ML-KEM key pairs...
          </Typography>
          <LinearProgress sx={{ mt: 1 }} />
        </Alert>
      )}

      {!keyPair1 && !initializing && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          Waiting for key pair initialization...
        </Alert>
      )}

      <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)} sx={{ mb: 3 }}>
        <Tab label="Test 1: validateKeys Valid vs Invalid" />
        <Tab label="Test 2: validateKeys Null vs Invalid" />
        <Tab label="Test 3: validateKeys Key Types" />
        <Tab label="Test 4: Encryption Timing" />
        <Tab label="Test 5: Decryption Timing" />
      </Tabs>

      {/* Test 1 */}
      {tabValue === 0 && (
        <Card>
          <CardHeader title="Test 1: validateKeys() Timing - Valid vs Invalid Keys" />
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Tests that validateKeys() has consistent timing for valid keys vs
              invalid (empty) keys. This prevents attackers from learning about
              key validity through timing differences.
            </Typography>
            <Button
              variant="contained"
              onClick={runTest1}
              disabled={test1Running || !keyPair1}
              sx={{ mb: 2 }}
            >
              {test1Running ? "Running Test..." : "Run Test 1"}
            </Button>
            {test1Running && <LinearProgress sx={{ mb: 2 }} />}
            {renderTestResults(test1Results, "Test 1")}
          </CardContent>
        </Card>
      )}

      {/* Test 2 */}
      {tabValue === 1 && (
        <Card>
          <CardHeader title="Test 2: validateKeys() Timing - Null vs Invalid Keys" />
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Tests that validateKeys() has consistent timing for null keys vs
              invalid (empty) keys. This verifies the fix for the early return
              timing leak.
            </Typography>
            <Button
              variant="contained"
              onClick={runTest2}
              disabled={test2Running}
              sx={{ mb: 2 }}
            >
              {test2Running ? "Running Test..." : "Run Test 2"}
            </Button>
            {test2Running && <LinearProgress sx={{ mb: 2 }} />}
            {renderTestResults(test2Results, "Test 2")}
          </CardContent>
        </Card>
      )}

      {/* Test 3 */}
      {tabValue === 2 && (
        <Card>
          <CardHeader title="Test 3: validateKeys() Timing - Different Key Types" />
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Tests that validateKeys() has consistent timing regardless of key
              type (public key only, private key only, both keys, or empty).
            </Typography>
            <Button
              variant="contained"
              onClick={runTest3}
              disabled={test3Running}
              sx={{ mb: 2 }}
            >
              {test3Running ? "Running Test..." : "Run Test 3"}
            </Button>
            {test3Running && <LinearProgress sx={{ mb: 2 }} />}
            {renderTestResults(test3Results, "Test 3")}
          </CardContent>
        </Card>
      )}

      {/* Test 4 */}
      {tabValue === 3 && (
        <Card>
          <CardHeader title="Test 4: Encryption Timing - Valid vs Invalid Keys" />
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Tests that encrypt() has consistent timing for valid keys vs
              invalid (wrong format) keys. Uses 20 runs as ML-KEM encryption is
              slower (~20-30ms per operation).
            </Typography>
            <Button
              variant="contained"
              onClick={runTest4}
              disabled={test4Running || !keyPair1}
              sx={{ mb: 2 }}
            >
              {test4Running ? "Running Test..." : "Run Test 4"}
            </Button>
            {test4Running && <LinearProgress sx={{ mb: 2 }} />}
            {renderTestResults(test4Results, "Test 4")}
          </CardContent>
        </Card>
      )}

      {/* Test 5 */}
      {tabValue === 4 && (
        <Card>
          <CardHeader title="Test 5: Decryption Timing - Valid vs Invalid Keys" />
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Tests that decrypt() has consistent timing for valid keys vs
              invalid (wrong private key) keys. Uses 20 runs as ML-KEM decryption
              is slower (~20-30ms per operation).
            </Typography>
            <Button
              variant="contained"
              onClick={runTest5}
              disabled={test5Running || !keyPair1 || !keyPair2}
              sx={{ mb: 2 }}
            >
              {test5Running ? "Running Test..." : "Run Test 5"}
            </Button>
            {test5Running && <LinearProgress sx={{ mb: 2 }} />}
            {renderTestResults(test5Results, "Test 5")}
          </CardContent>
        </Card>
      )}

      <Alert severity="info" sx={{ mt: 4 }}>
        <Typography variant="body2">
          <strong>Note:</strong> These tests run in a browser environment using
          the Web Crypto API. Timing measurements may vary due to browser
          optimizations, garbage collection, and other factors. The 75% variance
          threshold accounts for JavaScript timing variability while still
          detecting significant timing leaks.
        </Typography>
      </Alert>
    </Container>
  );
};

export const MLKEMTimingTests = () => <MLKEMTimingTestsDemo />;

MLKEMTimingTests.storyName = "ML-KEM Timing Attack Protection Tests";

