/**
 * ML-KEM Tutorial - Encapsulation Box Demo
 * Visual demonstration of key encapsulation
 */

import React, { useState } from "react";
import { MlKem768 } from "@hpke/ml-kem";
import { MLKEMCipherLayer } from "../../crypto/CascadingCipher";
import {
  ThemeProvider,
  Container,
  Typography,
  Button, Card,
  CardContent,
  Alert,
  Stack,
  Paper,
  TextField,
  Box,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const EncapsulationBox = () => {
  const [keyPair, setKeyPair] = useState(null);
  const [message, setMessage] = useState("Hello from Alice!");
  const [encrypted, setEncrypted] = useState(null);
  const [logs, setLogs] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [publicKeyInput, setPublicKeyInput] = useState("");
  const [ciphertextHex, setCiphertextHex] = useState("");

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time: timestamp, message: msg, type }]);
  };

  const generateKeys = async () => {
    setProcessing(true);
    try {
      addLog("Creating dummy key pair for demo...", "info");
      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();
      setKeyPair(pair);
      
      // Generate public key hex
      const pubHex = Array.from(pair.publicKey.key)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setPublicKeyInput(pubHex);
      
      addLog("✅ Key pair ready", "success");
      addLog(`   Public key (hex): ${pubHex.substring(0, 64)}...`, "info");
    } catch (err) {
      addLog(`❌ Error: ${err.message}`, "error");
    }
    setProcessing(false);
  };

  const encapsulate = async () => {
    if (!keyPair) return;
    setProcessing(true);
    setLogs([]);

    try {
      addLog("Step 1: Alice generates random secret K...", "info");
      addLog("   (In ML-KEM: Alice creates 32-byte shared secret)", "info");

      addLog("Step 2: Alice gets Bob's public key...", "info");
      addLog("   Public key contains matrix A and vector t", "info");

      addLog("Step 3: Alice picks random vector u...", "info");
      addLog("   (Each coefficient is small: -2 to 2)", "info");

      addLog("Step 4: Alice picks error vectors e1, e2...", "info");
      addLog("   (Adds tiny fog - makes puzzle hard)", "info");

      addLog("Step 5: Alice computes ciphertext...", "info");
      addLog("   c1 = Aᵀ·u + e1", "info");
      addLog("   c2 = t·u + e2 + m", "info");

      const start = performance.now();
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode(message);

      const result = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      const time = performance.now() - start;

      setEncrypted(result);
      
      // Convert ciphertext to hex for display
      const cipherBytes = new Uint8Array([
        ...result.parameters.encapsulated,
        ...result.ciphertext.filter(b => b !== undefined).slice(result.parameters.encapsulated.length),
      ]);
      const cipherHex = Array.from(cipherBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setCiphertextHex(cipherHex);

      addLog(`✅ Encapsulation complete in ${time.toFixed(2)}ms`, "success");
      addLog(`   Encapsulated key: ${result.parameters.encapsulated.length} bytes`, "info");
      addLog(`   Ciphertext: ${result.ciphertext.length} bytes`, "info");
      addLog(`   Combined: ${cipherBytes.length} bytes total`, "info");

      addLog("\nEncrypted ciphertext (hex):", "info");
      addLog(cipherHex.substring(0, 128) + "...", "info");

      addLog("\nStory Summary:", "info");
      addLog("- Alice put secret K in magic box using Bob's map", "info");
      addLog("- Anyone (even Alice) can close the box", "info");
      addLog("- Only Bob (with secret s) can open it!", "info");
    } catch (err) {
      addLog(`❌ Error: ${err.message}`, "error");
    }
    setProcessing(false);
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Encapsulation: Putting Secrets in Boxes
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Watch Alice put a secret key in Bob's magic lockbox. Anyone can close it, only Bob can open it!
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Stack spacing={3}>
              {!keyPair && (
                <Button variant="contained" onClick={generateKeys} disabled={processing}>
                  {processing ? "Generating..." : "Create Shared Key Pair"}
                </Button>
              )}

              {keyPair && !encrypted && (
                <>
                  <TextField
                    fullWidth
                    label="Message to Send"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    multiline
                    rows={2}
                  />

                  <Button
                    variant="contained"
                    onClick={encapsulate}
                    disabled={processing}
                    fullWidth
                  >
                    {processing ? "Encapsulating..." : "Put Secret in Magic Box"}
                  </Button>
                </>
              )}

              {encrypted && (
                <Alert severity="success">
                  Message Encapsulated! Bob's magic box now contains the shared secret key.
                  <br/>
                  Encapsulated key: {encrypted.parameters.encapsulated.length} bytes
                  <br/>
                  Encrypted ciphertext: {encrypted.ciphertext.length - encrypted.parameters.encapsulated.length} bytes
                </Alert>
              )}

              {/* Encrypted data display */}
              {encrypted && ciphertextHex && (
                <Paper sx={{ p: 2, mt: 2, bgcolor: "warning.light" }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ color: "text.primary" }}>
                    Encrypted Ciphertext (Hex)
                  </Typography>
                  <Typography variant="caption" sx={{ display: "block", mb: 1, color: "text.primary" }}>
                    This is the encrypted data Alice sends to Bob. Bob needs this + his private key to recover the secret!
                  </Typography>
                  <TextField
                    fullWidth
                    value={ciphertextHex}
                    multiline
                    rows={4}
                    size="small"
                    sx={{ fontFamily: "monospace", fontSize: "0.65rem", wordBreak: "break-all", bgcolor: "background.paper", "& .MuiInputBase-input": { color: "text.primary" } }}
                    helperText="Copy and paste this ciphertext to Bob. Bob will use it with his private key to recover the secret."
                  />
                  <Typography variant="caption" sx={{ display: "block", mt: 1, color: "text.primary" }}>
                    Start: {ciphertextHex.substring(0, 64)}...
                  </Typography>
                </Paper>
              )}

              {logs.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" sx={{ color: "text.primary" }}>Encapsulation Steps:</Typography>
                  <Box sx={{ maxHeight: 200, overflow: "auto", bgcolor: "grey.100", p: 2, borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                    {logs.map((log, i) => (
                      <Typography key={i} sx={{ color: log.type === "error" ? "error.main" : log.type === "success" ? "success.main" : "text.primary", mb: 0.5, whiteSpace: "pre-wrap" }}>
                        [{log.time}] {log.message}
                      </Typography>
                    ))}
                  </Box>
                </Box>
              )}

              <Paper sx={{ p: 2, bgcolor: "warning.light" }}>
                <Typography variant="subtitle2" sx={{ color: "text.primary" }}>How It Works</Typography>
                <Typography variant="body2" sx={{ color: "text.primary" }}>
                  Alice picks random K, uses Bob's public key to wrap K in ciphertext C.
                  Bob receives C, uses his secret s to unwrap and get the same K!
                </Typography>
              </Paper>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const EncapBox = () => <EncapsulationBox />;