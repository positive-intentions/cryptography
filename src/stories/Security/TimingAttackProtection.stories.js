import React, { useState } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import { AESCipherLayer } from '../../crypto/CascadingCipher/layers/AESCipherLayer';
import {
  CryptoDemo,
  CodeDisplay,
  OperationStatus,
  Button,
  TextField,
  Box,
  Typography,
  Stack,
  Card,
  CardContent,
  CardHeader,
  Alert,
  Grid,
  Paper,
  LinearProgress,
  Tabs,
  Tab,
  RadioGroup,
  FormControlLabel,
  Radio,
} from 'ui';

export default {
  title: 'Cryptography/Security/Timing Attack Protection',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'Demonstration of timing attack protection through consistent operation timing.',
      },
    },
  },
};

const TimingAttackProtectionDemo = () => {
  const [tabValue, setTabValue] = useState(0);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [message, setMessage] = useState('Test message for timing analysis');
  
  // Constant-time comparison state
  const [ctRunning, setCtRunning] = useState(false);
  const [ctResults, setCtResults] = useState(null);
  const [ctString1, setCtString1] = useState('test-string-123');
  const [ctString2, setCtString2] = useState('test-string-123');
  const [ctBuffer1, setCtBuffer1] = useState('');
  const [ctBuffer2, setCtBuffer2] = useState('');
  const [ctTestRuns, setCtTestRuns] = useState(100);
  const [ctTestType, setCtTestType] = useState('string');

  const measureTiming = async (operation, runs = 50) => {
    const timings = [];
    for (let i = 0; i < runs; i++) {
      const start = performance.now();
      try {
        await operation();
      } catch (e) {
        // Ignore errors, we're measuring timing
      }
      const end = performance.now();
      timings.push(end - start);
    }
    return timings;
  };

  const calculateStats = (timings) => {
    const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
    const stdDev = Math.sqrt(variance);
    const min = Math.min(...timings);
    const max = Math.max(...timings);
    const coefficientOfVariation = stdDev / mean;

    return { mean, stdDev, min, max, coefficientOfVariation };
  };

  const runTimingTest = async () => {
    setRunning(true);
    setResults(null);

    try {
      const layer = new AESCipherLayer();
      const keys = { password: 'test-password' };
      const plaintext = new TextEncoder().encode(message);

      // Encrypt
      const encrypted = await layer.encrypt(plaintext, keys);

      // Measure valid decryption timing
      const validTimings = await measureTiming(async () => {
        await layer.decrypt(encrypted, keys);
      });

      // Measure invalid decryption timing (wrong password)
      const invalidKeys = { password: 'wrong-password' };
      const invalidTimings = await measureTiming(async () => {
        try {
          await layer.decrypt(encrypted, invalidKeys);
        } catch (e) {
          // Expected error
        }
      });

      const validStats = calculateStats(validTimings);
      const invalidStats = calculateStats(invalidTimings);

      // Calculate variance between valid and invalid
      const variance = Math.abs(validStats.mean - invalidStats.mean) / Math.max(validStats.mean, invalidStats.mean);

      setResults({
        valid: validStats,
        invalid: invalidStats,
        variance,
        consistent: variance < 0.5, // 50% variance threshold
      });
    } catch (error) {
      setResults({
        error: error.message,
      });
    } finally {
      setRunning(false);
    }
  };

  const runConstantTimeTest = async () => {
    setCtRunning(true);
    setCtResults(null);

    try {
      const { ConstantTime } = await import('../../crypto/utils/constantTime.ts');

      if (ctTestType === 'string') {
        // String comparison test
        const measureTiming = (operation, runs) => {
          const timings = [];
          for (let i = 0; i < runs; i++) {
            const start = performance.now();
            operation();
            const end = performance.now();
            timings.push(end - start);
          }
          return timings;
        };

        const calculateStats = (timings) => {
          const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
          const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
          const stdDev = Math.sqrt(variance);
          const min = Math.min(...timings);
          const max = Math.max(...timings);
          const coefficientOfVariation = stdDev / mean;
          return { mean, stdDev, min, max, coefficientOfVariation };
        };

        // Test constant-time comparison
        const ctMatch = ctString1 === ctString2;
        const ctTimingsMatch = measureTiming(() => {
          ConstantTime.constantTimeCompareStrings(ctString1, ctString2);
        }, ctTestRuns);

        const ctTimingsMismatch = measureTiming(() => {
          ConstantTime.constantTimeCompareStrings(ctString1, ctString1 + 'x');
        }, ctTestRuns);

        // Test regular comparison
        const regularTimingsMatch = measureTiming(() => {
          // eslint-disable-next-line eqeqeq
          return ctString1 == ctString2;
        }, ctTestRuns);

        const regularTimingsMismatch = measureTiming(() => {
          // eslint-disable-next-line eqeqeq
          return ctString1 == (ctString1 + 'x');
        }, ctTestRuns);

        const ctStatsMatch = calculateStats(ctTimingsMatch);
        const ctStatsMismatch = calculateStats(ctTimingsMismatch);
        const regularStatsMatch = calculateStats(regularTimingsMatch);
        const regularStatsMismatch = calculateStats(regularTimingsMismatch);

        const ctVariance = Math.abs(ctStatsMatch.mean - ctStatsMismatch.mean) / 
          Math.max(ctStatsMatch.mean, ctStatsMismatch.mean);
        const regularVariance = Math.abs(regularStatsMatch.mean - regularStatsMismatch.mean) / 
          Math.max(regularStatsMatch.mean, regularStatsMismatch.mean);

        setCtResults({
          type: 'string',
          match: ctMatch,
          constantTime: {
            match: ctStatsMatch,
            mismatch: ctStatsMismatch,
            variance: ctVariance,
          },
          regular: {
            match: regularStatsMatch,
            mismatch: regularStatsMismatch,
            variance: regularVariance,
          },
          timings: {
            constantTimeMatch: ctTimingsMatch,
            constantTimeMismatch: ctTimingsMismatch,
            regularMatch: regularTimingsMatch,
            regularMismatch: regularTimingsMismatch,
          },
        });
      } else {
        // Buffer comparison test
        const buf1 = new TextEncoder().encode(ctBuffer1 || 'test-buffer-123');
        const buf2 = new TextEncoder().encode(ctBuffer2 || 'test-buffer-123');

        const measureTiming = (operation, runs) => {
          const timings = [];
          for (let i = 0; i < runs; i++) {
            const start = performance.now();
            operation();
            const end = performance.now();
            timings.push(end - start);
          }
          return timings;
        };

        const calculateStats = (timings) => {
          const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
          const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
          const stdDev = Math.sqrt(variance);
          const min = Math.min(...timings);
          const max = Math.max(...timings);
          const coefficientOfVariation = stdDev / mean;
          return { mean, stdDev, min, max, coefficientOfVariation };
        };

        const { ConstantTime } = await import('../../crypto/utils/constantTime.ts');
        const ctMatch = ConstantTime.constantTimeCompareBuffers(buf1, buf2);

        // Test with differences at different positions
        const bufStart = new Uint8Array(buf1);
        bufStart[0] = bufStart[0] === 255 ? 0 : 255;
        const bufMiddle = new Uint8Array(buf1);
        bufMiddle[Math.floor(buf1.length / 2)] = bufMiddle[Math.floor(buf1.length / 2)] === 255 ? 0 : 255;
        const bufEnd = new Uint8Array(buf1);
        bufEnd[buf1.length - 1] = bufEnd[buf1.length - 1] === 255 ? 0 : 255;

        const ctTimingsMatch = measureTiming(() => {
          ConstantTime.constantTimeCompareBuffers(buf1, buf2);
        }, ctTestRuns);

        const ctTimingsStart = measureTiming(() => {
          ConstantTime.constantTimeCompareBuffers(buf1, bufStart);
        }, ctTestRuns);

        const ctTimingsMiddle = measureTiming(() => {
          ConstantTime.constantTimeCompareBuffers(buf1, bufMiddle);
        }, ctTestRuns);

        const ctTimingsEnd = measureTiming(() => {
          ConstantTime.constantTimeCompareBuffers(buf1, bufEnd);
        }, ctTestRuns);

        const ctStatsMatch = calculateStats(ctTimingsMatch);
        const ctStatsStart = calculateStats(ctTimingsStart);
        const ctStatsMiddle = calculateStats(ctTimingsMiddle);
        const ctStatsEnd = calculateStats(ctTimingsEnd);

        const varianceStart = Math.abs(ctStatsMatch.mean - ctStatsStart.mean) / 
          Math.max(ctStatsMatch.mean, ctStatsStart.mean);
        const varianceMiddle = Math.abs(ctStatsMatch.mean - ctStatsMiddle.mean) / 
          Math.max(ctStatsMatch.mean, ctStatsMiddle.mean);
        const varianceEnd = Math.abs(ctStatsMatch.mean - ctStatsEnd.mean) / 
          Math.max(ctStatsMatch.mean, ctStatsEnd.mean);

        setCtResults({
          type: 'buffer',
          match: ctMatch,
          constantTime: {
            match: ctStatsMatch,
            start: ctStatsStart,
            middle: ctStatsMiddle,
            end: ctStatsEnd,
            varianceStart,
            varianceMiddle,
            varianceEnd,
          },
          timings: {
            match: ctTimingsMatch,
            start: ctTimingsStart,
            middle: ctTimingsMiddle,
            end: ctTimingsEnd,
          },
        });
      }
    } catch (error) {
      setCtResults({
        error: error.message,
      });
    } finally {
      setCtRunning(false);
    }
  };

  return (
    <CryptoDemo title="Timing Attack Protection Demo">
      <Stack spacing={3}>
        <Alert severity="info">
          <Typography variant="body2">
            <strong>Timing Attack Protection:</strong> Cryptographic operations should have consistent timing
            regardless of whether they succeed or fail. This prevents attackers from learning information
            through timing differences.
          </Typography>
        </Alert>

        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Cryptographic Operations" />
          <Tab label="Constant-Time Comparison" />
        </Tabs>

        {tabValue === 0 && (
          <>
            <Card>
              <CardHeader title="Test Configuration" />
              <CardContent>
                <Stack spacing={2}>
                  <TextField
                    label="Test Message"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    fullWidth
                  />
                  <Button
                    variant="contained"
                    onClick={runTimingTest}
                    disabled={running}
                  >
                    Run Timing Analysis
                  </Button>
                  {running && (
                    <Box>
                      <Typography variant="body2" gutterBottom>Running timing tests...</Typography>
                      <LinearProgress />
                    </Box>
                  )}
                </Stack>
              </CardContent>
            </Card>

            {results && (
          <>
            {results.error ? (
              <Alert severity="error">{results.error}</Alert>
            ) : (
              <>
                <Card>
                  <CardHeader title="Timing Statistics" />
                  <CardContent>
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6}>
                        <Paper sx={{ p: 2 }}>
                          <Typography variant="h6" gutterBottom>Valid Decryption</Typography>
                          <Stack spacing={1}>
                            <Typography variant="body2">Mean: {results.valid.mean.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Std Dev: {results.valid.stdDev.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Min: {results.valid.min.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Max: {results.valid.max.toFixed(2)}ms</Typography>
                            <Typography variant="body2">CV: {(results.valid.coefficientOfVariation * 100).toFixed(1)}%</Typography>
                          </Stack>
                        </Paper>
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <Paper sx={{ p: 2 }}>
                          <Typography variant="h6" gutterBottom>Invalid Decryption</Typography>
                          <Stack spacing={1}>
                            <Typography variant="body2">Mean: {results.invalid.mean.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Std Dev: {results.invalid.stdDev.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Min: {results.invalid.min.toFixed(2)}ms</Typography>
                            <Typography variant="body2">Max: {results.invalid.max.toFixed(2)}ms</Typography>
                            <Typography variant="body2">CV: {(results.invalid.coefficientOfVariation * 100).toFixed(1)}%</Typography>
                          </Stack>
                        </Paper>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="Timing Consistency Analysis" />
                  <CardContent>
                    <Stack spacing={2}>
                      <Typography variant="body1">
                        Variance between valid and invalid: {(results.variance * 100).toFixed(1)}%
                      </Typography>
                      <OperationStatus
                        status={results.consistent ? 'success' : 'warning'}
                        message={
                          results.consistent
                            ? 'Timing is consistent - timing attacks are mitigated'
                            : 'Timing variance is high - may leak information (Note: JavaScript timing is not perfectly consistent)'
                        }
                      />
                      <Alert severity="info">
                        <Typography variant="body2">
                          Note: JavaScript timing is inherently variable due to event loop, garbage collection,
                          and other factors. This test demonstrates the concept, but perfect timing consistency
                          is difficult to achieve in JavaScript environments.
                        </Typography>
                      </Alert>
                    </Stack>
                  </CardContent>
                </Card>
              </>
            )}
          </>
        )}

            <Card>
              <CardHeader title="Protection Mechanisms" />
              <CardContent>
                <Stack spacing={1}>
                  <Typography variant="body2">• Constant-time operations where possible</Typography>
                  <Typography variant="body2">• Consistent error handling paths</Typography>
                  <Typography variant="body2">• Statistical timing analysis</Typography>
                  <Typography variant="body2">• Awareness of timing side channels</Typography>
                </Stack>
              </CardContent>
            </Card>
          </>
        )}

        {tabValue === 1 && (
          <>
            <Card>
              <CardHeader title="Constant-Time Comparison Testing" />
              <CardContent>
                <Stack spacing={2}>
                  <Alert severity="info">
                    <Typography variant="body2">
                      <strong>Constant-Time Comparison:</strong> Compare strings and buffers using constant-time
                      algorithms to prevent timing attacks. This is critical for security-sensitive operations
                      like key fingerprint verification.
                    </Typography>
                  </Alert>

                  <Typography variant="subtitle2" gutterBottom>Test Type</Typography>
                  <RadioGroup
                    row
                    value={ctTestType}
                    onChange={(e) => setCtTestType(e.target.value)}
                  >
                    <FormControlLabel value="string" control={<Radio />} label="String Comparison" />
                    <FormControlLabel value="buffer" control={<Radio />} label="Buffer Comparison" />
                  </RadioGroup>

                  {ctTestType === 'string' ? (
                    <>
                      <TextField
                        label="String 1"
                        value={ctString1}
                        onChange={(e) => setCtString1(e.target.value)}
                        fullWidth
                      />
                      <TextField
                        label="String 2"
                        value={ctString2}
                        onChange={(e) => setCtString2(e.target.value)}
                        fullWidth
                      />
                    </>
                  ) : (
                    <>
                      <TextField
                        label="Buffer 1 (text)"
                        value={ctBuffer1}
                        onChange={(e) => setCtBuffer1(e.target.value)}
                        placeholder="test-buffer-123"
                        fullWidth
                      />
                      <TextField
                        label="Buffer 2 (text)"
                        value={ctBuffer2}
                        onChange={(e) => setCtBuffer2(e.target.value)}
                        placeholder="test-buffer-123"
                        fullWidth
                      />
                    </>
                  )}

                  <TextField
                    label="Number of Test Runs"
                    type="number"
                    value={ctTestRuns}
                    onChange={(e) => setCtTestRuns(parseInt(e.target.value) || 100)}
                    inputProps={{ min: 10, max: 1000 }}
                    fullWidth
                  />

                  <Button
                    variant="contained"
                    onClick={runConstantTimeTest}
                    disabled={ctRunning}
                  >
                    Run Constant-Time Comparison Test
                  </Button>

                  {ctRunning && (
                    <Box>
                      <Typography variant="body2" gutterBottom>Running constant-time tests...</Typography>
                      <LinearProgress />
                    </Box>
                  )}
                </Stack>
              </CardContent>
            </Card>

            {ctResults && (
              <>
                {ctResults.error ? (
                  <Alert severity="error">{ctResults.error}</Alert>
                ) : ctResults.type === 'string' ? (
                  <>
                    <Card>
                      <CardHeader title="String Comparison Results" />
                      <CardContent>
                        <Stack spacing={2}>
                          <OperationStatus
                            status={ctResults.match ? 'success' : 'warning'}
                            message={ctResults.match ? 'Strings match' : 'Strings do not match'}
                          />

                          <Typography variant="h6">Constant-Time Comparison</Typography>
                          <Grid container spacing={2}>
                            <Grid item xs={12} sm={6}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Match</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.match.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Std Dev: {ctResults.constantTime.match.stdDev.toFixed(4)}ms</Typography>
                                <Typography variant="body2">CV: {(ctResults.constantTime.match.coefficientOfVariation * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={12} sm={6}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Mismatch</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.mismatch.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Std Dev: {ctResults.constantTime.mismatch.stdDev.toFixed(4)}ms</Typography>
                                <Typography variant="body2">CV: {(ctResults.constantTime.mismatch.coefficientOfVariation * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                          </Grid>

                          <Typography variant="body1">
                            Timing Variance: {(ctResults.constantTime.variance * 100).toFixed(2)}%
                          </Typography>
                          <OperationStatus
                            status={ctResults.constantTime.variance < 0.3 ? 'success' : 'warning'}
                            message={
                              ctResults.constantTime.variance < 0.3
                                ? 'Timing is consistent - timing attacks mitigated'
                                : 'Timing variance is high - may leak information'
                            }
                          />

                          <Typography variant="h6">Regular Comparison (for comparison)</Typography>
                          <Grid container spacing={2}>
                            <Grid item xs={12} sm={6}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Match</Typography>
                                <Typography variant="body2">Mean: {ctResults.regular.match.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Std Dev: {ctResults.regular.match.stdDev.toFixed(4)}ms</Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={12} sm={6}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Mismatch</Typography>
                                <Typography variant="body2">Mean: {ctResults.regular.mismatch.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Std Dev: {ctResults.regular.mismatch.stdDev.toFixed(4)}ms</Typography>
                              </Paper>
                            </Grid>
                          </Grid>

                          <Typography variant="body1">
                            Regular Comparison Variance: {(ctResults.regular.variance * 100).toFixed(2)}%
                          </Typography>
                        </Stack>
                      </CardContent>
                    </Card>
                  </>
                ) : (
                  <>
                    <Card>
                      <CardHeader title="Buffer Comparison Results" />
                      <CardContent>
                        <Stack spacing={2}>
                          <OperationStatus
                            status={ctResults.match ? 'success' : 'warning'}
                            message={ctResults.match ? 'Buffers match' : 'Buffers do not match'}
                          />

                          <Typography variant="h6">Timing by Difference Position</Typography>
                          <Grid container spacing={2}>
                            <Grid item xs={12} sm={4}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Match</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.match.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">CV: {(ctResults.constantTime.match.coefficientOfVariation * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={12} sm={4}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Difference at Start</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.start.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Variance: {(ctResults.constantTime.varianceStart * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={12} sm={4}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Difference at Middle</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.middle.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Variance: {(ctResults.constantTime.varianceMiddle * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                            <Grid item xs={12} sm={4}>
                              <Paper sx={{ p: 2 }}>
                                <Typography variant="subtitle1" gutterBottom>Difference at End</Typography>
                                <Typography variant="body2">Mean: {ctResults.constantTime.end.mean.toFixed(4)}ms</Typography>
                                <Typography variant="body2">Variance: {(ctResults.constantTime.varianceEnd * 100).toFixed(2)}%</Typography>
                              </Paper>
                            </Grid>
                          </Grid>

                          <Alert severity="info">
                            <Typography variant="body2">
                              Constant-time comparison ensures timing doesn't vary based on where differences occur.
                              All variance values should be &lt; 30% for effective timing attack mitigation.
                            </Typography>
                          </Alert>
                        </Stack>
                      </CardContent>
                    </Card>
                  </>
                )}

                <Card>
                  <CardHeader title="Why Constant-Time Matters" />
                  <CardContent>
                    <Stack spacing={1}>
                      <Typography variant="body2">
                        • <strong>Timing Attacks:</strong> Attackers can learn information by measuring how long operations take
                      </Typography>
                      <Typography variant="body2">
                        • <strong>Fingerprint Verification:</strong> Regular string comparison leaks information about which characters match
                      </Typography>
                      <Typography variant="body2">
                        • <strong>Constant-Time Solution:</strong> Always compares all characters/bytes regardless of early differences
                      </Typography>
                      <Typography variant="body2">
                        • <strong>JavaScript Limitations:</strong> Perfect constant-time is impossible due to JIT compilation,
                        but this implementation significantly reduces timing variance
                      </Typography>
                    </Stack>
                  </CardContent>
                </Card>
              </>
            )}
          </>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const TimingProtection = {
  render: () => (
    <CryptographyProvider>
      <TimingAttackProtectionDemo />
    </CryptographyProvider>
  ),
};

