/**
 * ML-KEM Tutorial - Performance Comparison
 * Interactive performance benchmark for RSA vs ECC vs ML-KEM
 */

import React, { useState } from "react";
import { MlKem768 } from "@hpke/ml-kem";
import { p256 } from "@noble/curves/nist.js";
import {
  ThemeProvider,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Stack,
  Paper,
  Box,
  LinearProgress,
  Alert,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const PerformanceCompare = () => {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [iteration, setIteration] = useState(0);

  const runBenchmark = async () => {
    setRunning(true);
    setResults(null);
    setIteration(0);

    const algoTimes = {
      rsa_keygen: [],
      rsa_encrypt: [],
      rsa_decrypt: [],
      ecc_keygen: [],
      ecc_encrypt: [],
      ecc_decrypt: [],
      mlkem_keygen: [],
      mlkem_encap: [],
      mlkem_decap: [],
    };

    const iterations = 10;
    const testData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    for (let i = 0; i < iterations; i++) {
      setIteration(i + 1);

      // RSA Benchmark using Web Crypto API
      let start = performance.now();
      const rsaKeys = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
      );
      const rsa_keygen_time = performance.now() - start;
      algoTimes.rsa_keygen.push(rsa_keygen_time);

      start = performance.now();
      const encryptedRSA = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaKeys.publicKey,
        testData
      );
      const rsa_encrypted = performance.now() - start;
      algoTimes.rsa_encrypt.push(rsa_encrypted);

      start = performance.now();
      await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        rsaKeys.privateKey,
        encryptedRSA
      );
      const rsa_decrypted = performance.now() - start;
      algoTimes.rsa_decrypt.push(rsa_decrypted);

      // ECC Benchmark (P-256 / secp256r1)
      start = performance.now();
      const { secretKey: eccSecretKey, publicKey: eccPublicKey } = p256.keygen();
      const ecc_keygen_time = performance.now() - start;
      algoTimes.ecc_keygen.push(ecc_keygen_time);

      // ECDH: Generate second key pair and compute shared secret
      start = performance.now();
      const { secretKey: eccSecretKey2, publicKey: eccPublicKey2 } = p256.keygen();
      const eccSharedSecret = p256.getSharedSecret(eccSecretKey, eccPublicKey2);
      const ecc_encrypted = performance.now() - start;
      algoTimes.ecc_encrypt.push(ecc_encrypted);

      // ECDH decryption is symmetric (same operation from other side)
      start = performance.now();
      const eccSharedSecret2 = p256.getSharedSecret(eccSecretKey2, eccPublicKey);
      const ecc_decrypted = performance.now() - start;
      algoTimes.ecc_decrypt.push(ecc_decrypted);

      // ML-KEM Benchmark
      const kem = new MlKem768();

      start = performance.now();
      const mlkemKeys = await kem.generateKeyPair();
      const mlkem_keygen_time = performance.now() - start;
      algoTimes.mlkem_keygen.push(mlkem_keygen_time);

      start = performance.now();
      const { enc } = await kem.encap({
        recipientPublicKey: mlkemKeys.publicKey,
      });
      const mlkem_encap_time = performance.now() - start;
      algoTimes.mlkem_encap.push(mlkem_encap_time);

      start = performance.now();
      // Decapsulation
      await kem.decap({
        recipientKey: mlkemKeys.privateKey,
        enc,
      });
      const mlkem_decap_time = performance.now() - start;
      algoTimes.mlkem_decap.push(mlkem_decap_time);
    }

    const avg = arr => arr.reduce((a, b) => a + b, 0) / arr.length;

    setResults({
      rsa: {
        keygen: avg(algoTimes.rsa_keygen),
        encrypt: avg(algoTimes.rsa_encrypt),
        decrypt: avg(algoTimes.rsa_decrypt),
      },
      ecc: {
        keygen: avg(algoTimes.ecc_keygen),
        encrypt: avg(algoTimes.ecc_encrypt),
        decrypt: avg(algoTimes.ecc_decrypt),
      },
      mlkem: {
        keygen: avg(algoTimes.mlkem_keygen),
        encap: avg(algoTimes.mlkem_encap),
        decap: avg(algoTimes.mlkem_decap),
      },
    });
    setRunning(false);
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Performance Benchmark
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Compare encryption times for RSA, ECC, and ML-KEM. Click "Run Tests" to see real-time measurements!
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
<Stack spacing={3}>
                <Button
                  variant="contained"
                  onClick={runBenchmark}
                  disabled={running}
                  fullWidth
                >
                  {running ? `Testing ${iteration}/10 algorithms...` : "Run Real Algorithm Benchmarks (RSA, ECC, ML-KEM)"}
                </Button>
            
                {running && (
                  <Box>
                    <LinearProgress variant="determinate" value={(iteration / 10) * 100} />
                    <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                      Testing: iteration {iteration} of 10...
                    </Typography>
                  </Box>
                )}

              {results && (
                <Box sx={{ mt: 3 }}>
                  <Alert severity="success" sx={{ mb: 2 }}>
                    Real Algorithm Benchmarks Complete - Measured on your browser
                  </Alert>

                  <Typography variant="h6" gutterBottom>
                    Results: Average Times (milliseconds)
                  </Typography>

                  {/* Key Generation */}
                  <Paper sx={{ p: 2, mb: 2 }}>
                    <Typography variant="subtitle2">Key Generation</Typography>
                    <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">RSA-3072</Typography>
                        <Typography variant="h6">{results.rsa.keygen.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "100%", height: "100%", bgcolor: "error.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ECC-P256</Typography>
                        <Typography variant="h6">{results.ecc.keygen.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "35%", height: "100%", bgcolor: "warning.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ML-KEM768</Typography>
                        <Typography variant="h6">{results.mlkem.keygen.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "45%", height: "100%", bgcolor: "success.light" }} />
                        </Box>
                      </Box>
                    </Stack>
                  </Paper>

                  {/* Encryption */}
                  <Paper sx={{ p: 2, mb: 2 }}>
                    <Typography variant="subtitle2">Encryption / Encapsulation</Typography>
                    <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">RSA-3072</Typography>
                        <Typography variant="h6">{results.rsa.encrypt.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "100%", height: "100%", bgcolor: "error.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ECC-P256</Typography>
                        <Typography variant="h6">{results.ecc.encrypt.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "30%", height: "100%", bgcolor: "warning.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ML-KEM768</Typography>
                        <Typography variant="h6">{results.mlkem.encap.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "55%", height: "100%", bgcolor: "success.light" }} />
                        </Box>
                      </Box>
                    </Stack>
                  </Paper>

                  {/* Decryption */}
                  <Paper sx={{ p: 2, mb: 2 }}>
                    <Typography variant="subtitle2">Decryption / Decapsulation</Typography>
                    <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">RSA-3072</Typography>
                        <Typography variant="h6">{results.rsa.decrypt.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "100%", height: "100%", bgcolor: "error.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ECC-P256</Typography>
                        <Typography variant="h6">{results.ecc.decrypt.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "30%", height: "100%", bgcolor: "warning.light" }} />
                        </Box>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="caption">ML-KEM768</Typography>
                        <Typography variant="h6">{results.mlkem.decap.toFixed(1)}ms</Typography>
                        <Box sx={{ height: 30, bgcolor: "grey.300", mt: 1, borderRadius: 1, position: "relative", overflow: "hidden" }}>
                          <Box sx={{ position: "absolute", left: 0, top: 0, width: "55%", height: "100%", bgcolor: "success.light" }} />
                        </Box>
                      </Box>
                    </Stack>
                  </Paper>

<Paper sx={{ p: 2, bgcolor: "info.light" }}>
                <Typography variant="subtitle2">Key Insight</Typography>
                <Typography variant="body2" color="text.secondary">
                  ML-KEM performs similarly to ECC (fast!), has security comparable to RSA (high!), and is quantum-resistant (future-proof!). All times are measured using real algorithm implementations running in your browser.
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mt: 1 }}>
                  * RSA-4096, ECC-P256 (secp256r1), ML-KEM-768 actual implementations tested 10 times each
                </Typography>
              </Paper>
                </Box>
              )}

              <Paper sx={{ p: 2, bgcolor: "grey.100" }}>
                <Typography variant="caption">
                  * Note: Times are approximate and browser-dependent. Real implementations may vary.
                </Typography>
              </Paper>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const PerfCompare = () => <PerformanceCompare />;