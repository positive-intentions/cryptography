/**
 * ML-KEM Tutorial - Key Generation Wizard
 * Step-by-step visualization of ML-KEM key generation
 */

import React, { useState } from "react";
import { MlKem768 } from "@hpke/ml-kem";
import {
  ThemeProvider,
  Container,
  Typography,
  Button,
  TextField,
  Card,
  CardContent,
  Alert,
  Stack,
  Paper,
  LinearProgress,
  Box,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const KeyGenWizard = () => {
  const [step, setStep] = useState(1);
  const [keyPair, setKeyPair] = useState(null);
  const [logs, setLogs] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [publicKeyInput, setPublicKeyInput] = useState("");
  const [privateKeyInput, setPrivateKeyInput] = useState("");

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time: timestamp, message: msg, type }]);
  };

  const generateKeys = async () => {
    setProcessing(true);
    setLogs([]);
    try {
      addLog("Step 1: Creating ML-KEM-768 instance...", "info");
      const kem = new MlKem768();

      addLog("Step 2: Generating 32-byte seed for matrix A...", "info");
      addLog("Step 3: Expanding seed to 3x3 polynomial matrix...", "info");

      const startTime = performance.now();
      const pair = await kem.generateKeyPair();
      const keyGenTime = performance.now() - startTime;

      addLog(`Step 4: Sampling secret vector s (small coefficients)...`, "info");
      addLog("Step 5: Sampling error vector e (small noise)...", "info");
      addLog("Step 6: Computing t = A*s + e (mod 3329)...", "info");

      setKeyPair(pair);
      addLog(`✅ Keys generated in ${keyGenTime.toFixed(2)}ms`, "success");
      addLog(`   Public key size: ${pair.publicKey.key.length} bytes`, "info");
      addLog(`   Private key size: ${pair.privateKey.key.length} bytes`, "info");

      addLog("\nSummary:", "info");
      addLog("- Public key (pk): Matrix A (from seed) + computed t", "info");
      addLog("- Private key (sk): Secret vector s (kept hidden)", "info");
      addLog("- Eve sees pk, can't reverse-engineer s!", "info");
      
      // Display keys in plain text (hex)
      const pubHex = Array.from(pair.publicKey.key)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const privHex = Array.from(pair.privateKey.key)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setPublicKeyInput(pubHex);
      setPrivateKeyInput(privHex);
    } catch (err) {
      addLog(`❌ Error: ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  const reset = () => {
    setStep(1);
    setKeyPair(null);
    setLogs([]);
    setPublicKeyInput("");
    setPrivateKeyInput("");
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Key Generation Wizard
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Watch Bob create his magic lockbox (public key) that anyone can use, but only he can open!
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Stack spacing={3}>
              {/* Progress Steps */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Process Overview
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={(step / 1) * 100}
                  sx={{ mb: 1 }}
                />
                <Stack direction="row" spacing={1}>
                  <Paper sx={{ px: 2, py: 1, bgcolor: "primary.light", flex: 1, display: "flex", alignItems: "center", justifyContent: "center", borderRadius: 1 }}>
                    <Typography variant="caption" color="primary.contrastText" sx={{ fontWeight: "bold" }}>
                      1. Generate Keys
                    </Typography>
                  </Paper>
                </Stack>
              </Box>

              {/* Main Content */}
              {!keyPair && (
                <Box>
                  <Typography variant="body2" gutterBottom>
                    Story So Far:
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                    Bob wants a lockbox. Here's how he makes it:
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: "grey.100", mb: 2 }}>
                    <Typography variant="body2">
                      1. Bob picks a tiny random seed (32 bytes)
                    </Typography>
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: "grey.100", mb: 2 }}>
                      <Typography variant="body2">
                      2. Seed expands to matrix A (grid of 9 polynomials)
                    </Typography>
                  </Paper>
                  <Paper sx={{ p: 2, bgcolor: "grey.100", mb: 2}}>
                      <Typography variant="body2">
                      3. Bob picks secret s (small values like -2 to 2)
                    </Typography>
                    </Paper>
                    <Paper sx={{ p: 2, bgcolor: "grey.100", mb: 2 }}>
                      <Typography variant="body2">
                      4. Bob adds tiny error e (fogs the location)
                    </Typography>
                    </Paper>
                    <Paper sx={{ p: 2, bgcolor: "grey.100", mb: 2 }}>
                    <Typography variant="body2">
                    5. Bob computes t = A*s + e (foggy map point)
                      </Typography>
                    </Paper>
                </Box>
              )}

              {/* Action Buttons */}
              <Stack direction="row" spacing={2}>
                <Button
                  variant="contained"
                  onClick={generateKeys}
                  disabled={processing || keyPair}
                  fullWidth
                >
                  {processing ? "Generating..." : "Generate Keys"}
                </Button>
                <Button
                  variant="outlined"
                  onClick={reset}
                  disabled={!keyPair}
                  fullWidth
                >
                  Reset
                </Button>
              </Stack>

              {processing && <LinearProgress />}

              {/* Results */}
              {keyPair && (
                <Box sx={{ mt: 3 }}>
                  <Alert severity="success" sx={{ mb: 2 }}>
                    Key Pair Generated!
                  </Alert>

                  <Paper sx={{ p: 2, bgcolor: "info.light", mb: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Public Key (pk) - Hex Representation
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                      Size: {keyPair.publicKey.key.length} bytes (~{(keyPair.publicKey.key.length / 1024).toFixed(2)} KB)
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 1, color: "text.secondary" }}>
                      Copy this public key and use it for encryption/encapsulation
                    </Typography>
                    <TextField
                      fullWidth
                      value={publicKeyInput}
                      onChange={(e) => setPublicKeyInput(e.target.value)}
                      multiline
                      rows={3}
                      size="small"
                      sx={{ fontFamily: "monospace", fontSize: "0.7rem", wordBreak: "break-all" }}
                      helperText="Copy and paste this public key to encrypt messages"
                    />
                  </Paper>

                  <Paper sx={{ p: 2, bgcolor: "error.light", mb: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Private Key (sk) - Hex Representation (KEEP SECRET!)
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                      Size: {keyPair.privateKey.key.length} bytes
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 1, color: "text.secondary" }}>
                      Store this private key securely - anyone with it can decrypt all your messages
                    </Typography>
                    <TextField
                      fullWidth
                      value={privateKeyInput}
                      onChange={(e) => setPrivateKeyInput(e.target.value)}
                      multiline
                      rows={2}
                      size="small"
                      sx={{ fontFamily: "monospace", fontSize: "0.7rem", wordBreak: "break-all" }}
                      helperText="Never share this private key!"
                    />
                  </Paper>

                  <Paper sx={{ p: 2, bgcolor: "grey.100" }}>
                    <Typography variant="caption" display="block" sx={{ mb: 1 }}>
                      How keys appear (in hex):
                    </Typography>
                    <Typography variant="body2" sx={{ display: "block", mb: 1 }}>
                      <strong>Public Key:</strong> {publicKeyInput.substring(0, 64)}...
                    </Typography>
                    <Typography variant="body2" sx={{ display: "block" }}>
                      <strong>Private Key:</strong> {privateKeyInput.substring(0, 64)}...
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mt: 1, color: "text.secondary" }}>
                      These hex strings represent the actual byte arrays used in ML-KEM operations
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", mt: 1, color: "info.main" }}>
                      Pro tip: You can copy and paste these keys to test encryption/decapsulation!
                    </Typography>
                  </Paper>
                </Box>
              )}

              {/* Manual key paste option */}
              {keyPair && (
                <Paper sx={{ p: 2, bgcolor: "grey.50", mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Or Paste Existing Keys to Test
                  </Typography>
                  <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                    If you have existing keys from another session, you can paste them here to see the format
                  </Typography>
                  <TextField
                    fullWidth
                    label="Paste Public Key (hex)"
                    placeholder="Paste public key hex string here..."
                    multiline
                    rows={2}
                    size="small"
                    sx={{ fontFamily: "monospace", fontSize: "0.7rem", mt: 1 }}
                    onChange={(e) => {
                      const pub = e.target.value;
                      const cleanHex = pub.replace(/[^0-9a-fA-F]/g, "");
                      setPublicKeyInput(cleanHex);
                      if (cleanHex.length > 0 && cleanHex.length % 2 === 0) {
                        addLog(`Public key pasted: ${cleanHex.length / 2} bytes`, "info");
                      }
                    }}
                  />
                  <TextField
                    fullWidth
                    label="Paste Private Key (hex) - For Decapsulation Testing!"
                    placeholder="Paste private key hex string here to test decapsulation..."
                    multiline
                    rows={2}
                    size="small"
                    sx={{ fontFamily: "monospace", fontSize: "0.7rem", mt: 2 }}
                    onChange={(e) => {
                      const priv = e.target.value;
                      const cleanHex = priv.replace(/[^0-9a-fA-F]/g, "");
                      setPrivateKeyInput(cleanHex);
                      if (cleanHex.length > 0 && cleanHex.length % 2 === 0) {
                        addLog(`Private key pasted: ${cleanHex.length / 2} bytes - For testing decapsulation only!`, "warning");
                      }
                    }}
                  />
                </Paper>
              )}

              {/* Log */}
              {logs.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Step-by-Step Log
                  </Typography>
                  <Box
                    sx={{
                      maxHeight: 200,
                      overflow: "auto",
                      bgcolor: "grey.50",
                      p: 2,
                      borderRadius: 1,
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                    }}
                  >
                    {logs.map((log, i) => (
                      <Typography
                        key={i}
                        sx={{
                          color:
                            log.type === "error" ? "error.main" :
                            log.type === "success" ? "success.main" :
                            log.type === "warning" ? "warning.dark" :
                            "text.primary",
                          mb: 0.5,
                          whiteSpace: "pre-wrap",
                        }}
                      >
                        [{log.time}] {log.message}
                      </Typography>
                    ))}
                  </Box>
                </Box>
              )}

              {/* ML-KEM Connection */}
              <Paper sx={{ p: 2, bgcolor: "success.light" }}>
                <Typography variant="subtitle2" gutterBottom>
                  ML-KEM Key Generation Algorithm
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  The formula: ${"\\mathbf{t} = \\mathbf{A}\\mathbf{s} + \\mathbf{e} \\pmod{q}"}$
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Where q = 3329. This is the Module Learning With Errors (MLWE) foundation making ML-KEM quantum-resistant!
                </Typography>
              </Paper>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const KeyGenWiz = () => <KeyGenWizard />;