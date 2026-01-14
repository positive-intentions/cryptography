/**
 * ML-KEM Beginner Tutorial Storybook Entries
 * 
 * Interactive demos for the ML-KEM beginner tutorial blog post.
 * Each story demonstrates a specific step in learning ML-KEM.
 */

import React, { useState } from "react";
import { MLKEMCipherLayer } from "../../crypto/CascadingCipher";
import { MlKem768 } from "@hpke/ml-kem";
import {
  ThemeProvider,
  Container,
  Paper,
  Typography,
  Button,
  TextField,
  Box,
  Stack,
  Chip,
  Alert,
  Card,
  CardContent,
  Divider,
  List,
  ListItem,
  ListItemText,
  Grid,
  LinearProgress,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Beginner Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

/**
 * Step 1: Key Generation Demo
 * Shows how to generate ML-KEM key pairs
 */
const Step1KeyGeneration = () => {
  const [keyPair, setKeyPair] = useState(null);
  const [publicKeyHex, setPublicKeyHex] = useState("");
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [processing, setProcessing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time: timestamp, message: msg, type }]);
  };

  const generateKeys = async () => {
    setProcessing(true);
    setLogs([]);
    setKeyPair(null);
    setPublicKeyHex("");
    setPrivateKeyHex("");

    try {
      addLog("🔑 Creating ML-KEM instance...", "info");
      addLog("🔑 Generating ML-KEM-768 key pair...", "info");
      const startTime = performance.now();

      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();

      const endTime = performance.now();
      const keyGenTime = endTime - startTime;

      setKeyPair(pair);

      const publicKeyBytes = pair.publicKey.key;
      const privateKeyBytes = pair.privateKey.key;

      const pubHex = Array.from(publicKeyBytes.slice(0, 32))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      const privHex = Array.from(privateKeyBytes.slice(0, 16))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");

      setPublicKeyHex(pubHex);
      setPrivateKeyHex(privHex);

      setMetrics({
        keyGenTime,
        publicKeySize: publicKeyBytes.length,
        privateKeySize: privateKeyBytes.length,
      });

      addLog(`✅ Key pair generated in ${keyGenTime.toFixed(2)}ms`, "success");
      addLog(`📊 Public key size: ${publicKeyBytes.length} bytes (~${(publicKeyBytes.length / 1024).toFixed(2)} KB)`, "info");
      addLog(`📊 Private key size: ${privateKeyBytes.length} bytes`, "info");
      addLog(`📤 Public key (first 32 bytes): ${pubHex}...`, "info");
      addLog(`🔐 Private key (first 16 bytes): ${privHex}...`, "info");
      addLog("💡 Tip: The public key is safe to share, but keep the private key secret!", "info");
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Step 1: Generate ML-KEM Key Pair
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        First, we need to generate a public/private key pair. The public key can be shared with anyone, while the private key must be kept secret.
      </Typography>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Button
            variant="contained"
            onClick={generateKeys}
            disabled={processing}
            fullWidth
            sx={{ mb: 3 }}
          >
            {processing ? "Generating..." : "Generate ML-KEM Key Pair"}
          </Button>

          {processing && <LinearProgress sx={{ mb: 2 }} />}

          {keyPair && (
            <Box sx={{ mt: 2 }}>
              <Alert severity="success" sx={{ mb: 2 }}>
                ✅ Key pair generated successfully!
              </Alert>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Public Key (first 32 bytes):
                  </Typography>
                  <Box
                    sx={{
                      p: 1.5,
                      bgcolor: "grey.100",
                      borderRadius: 1,
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      wordBreak: "break-all",
                    }}
                  >
                    {publicKeyHex}...
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                    Full size: {metrics?.publicKeySize} bytes (~{(metrics?.publicKeySize / 1024).toFixed(2)} KB)
                  </Typography>
                  <Chip label="Safe to share" color="success" size="small" sx={{ mt: 1 }} />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Private Key (first 16 bytes):
                  </Typography>
                  <Box
                    sx={{
                      p: 1.5,
                      bgcolor: "grey.100",
                      borderRadius: 1,
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      wordBreak: "break-all",
                    }}
                  >
                    {privateKeyHex}...
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                    Full size: {metrics?.privateKeySize} bytes
                  </Typography>
                  <Chip label="Keep secret!" color="error" size="small" sx={{ mt: 1 }} />
                </Grid>
              </Grid>

              {metrics && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Performance:
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Key generation time: {metrics.keyGenTime.toFixed(2)}ms
                  </Typography>
                </Box>
              )}
            </Box>
          )}

          {logs.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Operation Log:
              </Typography>
              <Box
                sx={{
                  maxHeight: 200,
                  overflow: "auto",
                  bgcolor: "grey.50",
                  p: 2,
                  borderRadius: 1,
                }}
              >
                {logs.map((log, i) => (
                  <Typography
                    key={i}
                    variant="body2"
                    sx={{
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      color:
                        log.type === "error"
                          ? "error.main"
                          : log.type === "success"
                            ? "success.main"
                            : "text.primary",
                      mb: 0.5,
                    }}
                  >
                    [{log.time}] {log.message}
                  </Typography>
                ))}
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

/**
 * Step 2: Encryption Demo
 * Shows how to encrypt a message using the public key
 */
const Step2Encryption = () => {
  const [keyPair, setKeyPair] = useState(null);
  const [message, setMessage] = useState("Hello, Quantum-Resistant World!");
  const [encrypted, setEncrypted] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time: timestamp, message: msg, type }]);
  };

  const generateKeys = async () => {
    setProcessing(true);
    setLogs([]);
    try {
      addLog("🔑 Generating key pair...", "info");
      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();
      setKeyPair(pair);
      addLog("✅ Key pair generated", "success");
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  const handleEncrypt = async () => {
    if (!keyPair) {
      addLog("⚠️ Please generate keys first", "error");
      return;
    }

    setProcessing(true);
    setEncrypted(null);
    setLogs([]);

    try {
      addLog("🔒 Starting ML-KEM encryption...", "info");
      const startTime = performance.now();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode(message);

      addLog(`📝 Plaintext: "${message}"`, "info");
      addLog(`📝 Plaintext size: ${plaintext.length} bytes`, "info");

      const result = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const endTime = performance.now();
      const encryptTime = endTime - startTime;

      setEncrypted(result);
      setMetrics({
        encryptTime,
        plaintextSize: plaintext.length,
        encapsulatedSize: result.parameters.encapsulated.length,
        ciphertextSize: result.ciphertext.length,
        overhead: result.ciphertext.length - plaintext.length,
      });

      addLog(`✅ Encryption complete in ${encryptTime.toFixed(2)}ms`, "success");
      addLog(`📊 Encapsulated key size: ${result.parameters.encapsulated.length} bytes`, "info");
      addLog(`📊 Ciphertext size: ${result.ciphertext.length} bytes`, "info");
      addLog(`📈 Size overhead: ${((result.ciphertext.length / plaintext.length - 1) * 100).toFixed(1)}%`, "info");
      addLog("💡 The encapsulated key contains the shared secret encrypted with the public key", "info");
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Step 2: Encrypt a Message
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Now we'll encrypt a message using the public key. ML-KEM creates a shared secret and uses it with AES-GCM to encrypt your data.
      </Typography>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          {!keyPair && (
            <Box sx={{ mb: 3 }}>
              <Button variant="outlined" onClick={generateKeys} disabled={processing}>
                Generate Keys First
              </Button>
            </Box>
          )}

          {keyPair && (
            <Alert severity="success" sx={{ mb: 2 }}>
              ✅ Key pair ready
            </Alert>
          )}

          <TextField
            fullWidth
            label="Message to Encrypt"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            margin="normal"
            multiline
            rows={3}
            disabled={processing || !keyPair}
          />

          <Button
            variant="contained"
            color="primary"
            onClick={handleEncrypt}
            disabled={processing || !keyPair || !message}
            fullWidth
            sx={{ mt: 2 }}
          >
            {processing ? "Encrypting..." : "🔒 Encrypt with Public Key"}
          </Button>

          {processing && <LinearProgress sx={{ mt: 2 }} />}

          {encrypted && (
            <Box sx={{ mt: 3 }}>
              <Alert severity="info" sx={{ mb: 2 }}>
                ✅ Message encrypted successfully
              </Alert>
              
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Encapsulated Key (first 32 bytes):
                  </Typography>
                  <Box
                    sx={{
                      p: 1.5,
                      bgcolor: "grey.100",
                      borderRadius: 1,
                      fontFamily: "monospace",
                      fontSize: "0.7rem",
                      wordBreak: "break-all",
                      maxHeight: 80,
                      overflow: "auto",
                    }}
                  >
                    {Array.from(encrypted.parameters.encapsulated.slice(0, 32))
                      .map((b) => b.toString(16).padStart(2, "0"))
                      .join(" ")}
                    ...
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                    Full size: {encrypted.parameters.encapsulated.length} bytes
                  </Typography>
                </Grid>
              </Grid>

              {metrics && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Encryption Metrics:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Encryption Time"
                        secondary={`${metrics.encryptTime.toFixed(2)}ms`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Plaintext Size"
                        secondary={`${metrics.plaintextSize} bytes`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Ciphertext Size"
                        secondary={`${metrics.ciphertextSize} bytes`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Size Overhead"
                        secondary={`${metrics.overhead} bytes (${((metrics.overhead / metrics.plaintextSize) * 100).toFixed(1)}%)`}
                      />
                    </ListItem>
                  </List>
                </Box>
              )}
            </Box>
          )}

          {logs.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Operation Log:
              </Typography>
              <Box
                sx={{
                  maxHeight: 200,
                  overflow: "auto",
                  bgcolor: "grey.50",
                  p: 2,
                  borderRadius: 1,
                }}
              >
                {logs.map((log, i) => (
                  <Typography
                    key={i}
                    variant="body2"
                    sx={{
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      color:
                        log.type === "error"
                          ? "error.main"
                          : log.type === "success"
                            ? "success.main"
                            : "text.primary",
                      mb: 0.5,
                    }}
                  >
                    [{log.time}] {log.message}
                  </Typography>
                ))}
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

/**
 * Step 3: Decryption Demo
 * Shows how to decrypt a message using the private key
 */
const Step3Decryption = () => {
  const [keyPair, setKeyPair] = useState(null);
  const [message, setMessage] = useState("Hello, Quantum-Resistant World!");
  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState("");
  const [processing, setProcessing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time: timestamp, message: msg, type }]);
  };

  const generateKeys = async () => {
    setProcessing(true);
    setLogs([]);
    try {
      addLog("🔑 Generating key pair...", "info");
      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();
      setKeyPair(pair);
      addLog("✅ Key pair generated", "success");
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  const handleEncrypt = async () => {
    if (!keyPair) return;
    setProcessing(true);
    setEncrypted(null);
    setDecrypted("");
    setLogs([]);

    try {
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode(message);
      const result = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });
      setEncrypted(result);
      addLog("✅ Message encrypted", "success");
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  const handleDecrypt = async () => {
    if (!encrypted || !keyPair) {
      addLog("⚠️ Please encrypt a message first", "error");
      return;
    }

    setProcessing(true);
    setDecrypted("");
    setLogs([]);

    try {
      addLog("🔓 Starting ML-KEM decryption...", "info");
      const startTime = performance.now();

      const layer = new MLKEMCipherLayer();
      const plaintextBytes = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      const endTime = performance.now();
      const decryptTime = endTime - startTime;

      const plaintextStr = new TextDecoder().decode(plaintextBytes);
      setDecrypted(plaintextStr);
      setMetrics({ decryptTime });

      addLog(`✅ Decryption complete in ${decryptTime.toFixed(2)}ms`, "success");
      addLog(`📝 Recovered message: "${plaintextStr}"`, "success");

      if (plaintextStr === message) {
        addLog("🎉 Round-trip successful! Message matches perfectly!", "success");
      } else {
        addLog("⚠️ Warning: Decrypted message does not match original", "error");
      }
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Step 3: Decrypt the Message
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Finally, we'll decrypt the message using the private key. ML-KEM extracts the shared secret and uses it to decrypt your data.
      </Typography>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Stack spacing={2}>
            {!keyPair && (
              <Button variant="outlined" onClick={generateKeys} disabled={processing}>
                Generate Keys First
              </Button>
            )}

            {keyPair && !encrypted && (
              <>
                <TextField
                  fullWidth
                  label="Message to Encrypt"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  margin="normal"
                  disabled={processing}
                />
                <Button variant="contained" onClick={handleEncrypt} disabled={processing}>
                  Encrypt First
                </Button>
              </>
            )}

            {encrypted && (
              <>
                <Alert severity="info">
                  ✅ Message encrypted. Now decrypt it!
                </Alert>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={handleDecrypt}
                  disabled={processing}
                  fullWidth
                >
                  {processing ? "Decrypting..." : "🔓 Decrypt with Private Key"}
                </Button>
              </>
            )}

            {processing && <LinearProgress />}

            {decrypted && (
              <Alert severity="success">
                <Typography variant="subtitle2">
                  Decrypted Message:
                </Typography>
                <Typography variant="body1" sx={{ fontWeight: "bold", mt: 1 }}>
                  {decrypted}
                </Typography>
                {decrypted === message && (
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                    ✅ Perfect match! Round-trip successful.
                  </Typography>
                )}
                {metrics && (
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                    Decryption time: {metrics.decryptTime.toFixed(2)}ms
                  </Typography>
                )}
              </Alert>
            )}

            {logs.length > 0 && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Operation Log:
                </Typography>
                <Box
                  sx={{
                    maxHeight: 200,
                    overflow: "auto",
                    bgcolor: "grey.50",
                    p: 2,
                    borderRadius: 1,
                  }}
                >
                  {logs.map((log, i) => (
                    <Typography
                      key={i}
                      variant="body2"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.75rem",
                        color:
                          log.type === "error"
                            ? "error.main"
                            : log.type === "success"
                              ? "success.main"
                              : "text.primary",
                        mb: 0.5,
                      }}
                    >
                      [{log.time}] {log.message}
                    </Typography>
                  ))}
                </Box>
              </Box>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Container>
  );
};

/**
 * Complete Example: Full round-trip
 */
const CompleteExample = () => {
  const [keyPair, setKeyPair] = useState(null);
  const [message, setMessage] = useState("This is a secret message!");
  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState("");
  const [processing, setProcessing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [step, setStep] = useState(1);

  const addLog = (msg, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time: timestamp, message: msg, type }]);
  };

  const runCompleteExample = async () => {
    setProcessing(true);
    setLogs([]);
    setStep(1);

    try {
      // Step 1: Generate keys
      addLog("🔑 Step 1: Generating ML-KEM key pair...", "info");
      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();
      setKeyPair(pair);
      addLog(`✅ Key pair generated!`, "success");
      addLog(`   Public key size: ${pair.publicKey.key.length} bytes`, "info");
      addLog(`   Private key size: ${pair.privateKey.key.length} bytes`, "info");
      setStep(2);

      await new Promise((resolve) => setTimeout(resolve, 500));

      // Step 2: Encrypt
      addLog("\n🔒 Step 2: Encrypting message...", "info");
      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode(message);
      addLog(`   Message: "${message}"`, "info");
      addLog(`   Message size: ${plaintext.length} bytes`, "info");

      const startEncrypt = performance.now();
      const result = await layer.encrypt(plaintext, {
        publicKey: pair.publicKey,
      });
      const encryptTime = performance.now() - startEncrypt;

      setEncrypted(result);
      addLog(`✅ Message encrypted in ${encryptTime.toFixed(2)}ms!`, "success");
      addLog(`   Encapsulated key size: ${result.parameters.encapsulated.length} bytes`, "info");
      addLog(`   Ciphertext size: ${result.ciphertext.length} bytes`, "info");
      setStep(3);

      await new Promise((resolve) => setTimeout(resolve, 500));

      // Step 3: Decrypt
      addLog("\n🔓 Step 3: Decrypting message...", "info");
      const startDecrypt = performance.now();
      const decryptedBytes = await layer.decrypt(result, {
        privateKey: pair.privateKey,
      });
      const decryptTime = performance.now() - startDecrypt;

      const decryptedStr = new TextDecoder().decode(decryptedBytes);
      setDecrypted(decryptedStr);
      addLog(`✅ Message decrypted in ${decryptTime.toFixed(2)}ms!`, "success");
      addLog(`   Decrypted: "${decryptedStr}"`, "success");

      if (decryptedStr === message) {
        addLog("\n🎉 Success! Round-trip encryption/decryption works perfectly!", "success");
      }
    } catch (err) {
      addLog(`❌ ${err.message}`, "error");
    } finally {
      setProcessing(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Complete Example: Full Round-Trip
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        This demo shows the complete ML-KEM workflow: key generation, encryption, and decryption all in one go.
      </Typography>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            label="Message to Encrypt"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            margin="normal"
            multiline
            rows={2}
            disabled={processing}
          />

          <Button
            variant="contained"
            onClick={runCompleteExample}
            disabled={processing}
            fullWidth
            sx={{ mt: 2 }}
          >
            {processing ? "Running..." : "🚀 Run Complete Example"}
          </Button>

          {processing && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: "center" }}>
                Step {step} of 3
              </Typography>
            </Box>
          )}

          {decrypted && (
            <Alert severity="success" sx={{ mt: 2 }}>
              <Typography variant="subtitle2">Original:</Typography>
              <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                {message}
              </Typography>
              <Typography variant="subtitle2" sx={{ mt: 1 }}>Decrypted:</Typography>
              <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                {decrypted}
              </Typography>
              {decrypted === message && (
                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                  ✅ Perfect match!
                </Typography>
              )}
            </Alert>
          )}

          {logs.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Operation Log:
              </Typography>
              <Box
                sx={{
                  maxHeight: 400,
                  overflow: "auto",
                  bgcolor: "grey.50",
                  p: 2,
                  borderRadius: 1,
                  fontFamily: "monospace",
                }}
              >
                {logs.map((log, i) => (
                  <Typography
                    key={i}
                    variant="body2"
                    sx={{
                      fontSize: "0.8rem",
                      color:
                        log.type === "error"
                          ? "error.main"
                          : log.type === "success"
                            ? "success.main"
                            : "text.primary",
                      mb: 0.5,
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {log.message}
                  </Typography>
                ))}
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

/**
 * Performance Analysis Demo
 */
const PerformanceAnalysis = () => {
  const [results, setResults] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [iterations, setIterations] = useState(10);

  const runBenchmark = async () => {
    setProcessing(true);
    setResults(null);

    try {
      const kem = new MlKem768();
      const layer = new MLKEMCipherLayer();
      const message = "Performance test message for ML-KEM benchmarking";

      const keyGenTimes = [];
      const encryptTimes = [];
      const decryptTimes = [];

      // Generate key pair once
      const keyPairStart = performance.now();
      const keyPair = await kem.generateKeyPair();
      const keyGenTime = performance.now() - keyPairStart;
      keyGenTimes.push(keyGenTime);

      // Run multiple iterations
      for (let i = 0; i < iterations; i++) {
        const plaintext = new TextEncoder().encode(`${message} ${i}`);

        // Encrypt
        const encryptStart = performance.now();
        const encrypted = await layer.encrypt(plaintext, {
          publicKey: keyPair.publicKey,
        });
        encryptTimes.push(performance.now() - encryptStart);

        // Decrypt
        const decryptStart = performance.now();
        await layer.decrypt(encrypted, {
          privateKey: keyPair.privateKey,
        });
        decryptTimes.push(performance.now() - decryptStart);
      }

      const avgKeyGen = keyGenTimes.reduce((a, b) => a + b, 0) / keyGenTimes.length;
      const avgEncrypt = encryptTimes.reduce((a, b) => a + b, 0) / encryptTimes.length;
      const avgDecrypt = decryptTimes.reduce((a, b) => a + b, 0) / decryptTimes.length;
      const minEncrypt = Math.min(...encryptTimes);
      const maxEncrypt = Math.max(...encryptTimes);
      const minDecrypt = Math.min(...decryptTimes);
      const maxDecrypt = Math.max(...decryptTimes);

      setResults({
        iterations,
        keyGen: {
          avg: avgKeyGen,
        },
        encrypt: {
          avg: avgEncrypt,
          min: minEncrypt,
          max: maxEncrypt,
        },
        decrypt: {
          avg: avgDecrypt,
          min: minDecrypt,
          max: maxDecrypt,
        },
      });
    } catch (err) {
      console.error(err);
    } finally {
      setProcessing(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Performance Analysis
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Benchmark ML-KEM operations to understand performance characteristics.
      </Typography>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            label="Number of Iterations"
            type="number"
            value={iterations}
            onChange={(e) => setIterations(parseInt(e.target.value) || 10)}
            margin="normal"
            disabled={processing}
            inputProps={{ min: 1, max: 100 }}
          />

          <Button
            variant="contained"
            onClick={runBenchmark}
            disabled={processing}
            fullWidth
            sx={{ mt: 2 }}
          >
            {processing ? "Running Benchmark..." : "🚀 Run Performance Benchmark"}
          </Button>

          {processing && <LinearProgress sx={{ mt: 2 }} />}

          {results && (
            <Box sx={{ mt: 3 }}>
              <Alert severity="success" sx={{ mb: 2 }}>
                ✅ Benchmark complete! ({results.iterations} iterations)
              </Alert>

              <List>
                <ListItem>
                  <ListItemText
                    primary="Key Generation"
                    secondary={`Average: ${results.keyGen.avg.toFixed(2)}ms`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Encryption"
                    secondary={`Average: ${results.encrypt.avg.toFixed(2)}ms | Min: ${results.encrypt.min.toFixed(2)}ms | Max: ${results.encrypt.max.toFixed(2)}ms`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Decryption"
                    secondary={`Average: ${results.decrypt.avg.toFixed(2)}ms | Min: ${results.decrypt.min.toFixed(2)}ms | Max: ${results.decrypt.max.toFixed(2)}ms`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Total Round-Trip"
                    secondary={`Average: ${(results.encrypt.avg + results.decrypt.avg).toFixed(2)}ms`}
                  />
                </ListItem>
              </List>
            </Box>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

// Export stories
export const Step1KeyGenerationStory = () => <Step1KeyGeneration />;
Step1KeyGenerationStory.storyName = "Step 1: Key Generation";

export const Step2EncryptionStory = () => <Step2Encryption />;
Step2EncryptionStory.storyName = "Step 2: Encryption";

export const Step3DecryptionStory = () => <Step3Decryption />;
Step3DecryptionStory.storyName = "Step 3: Decryption";

export const CompleteExampleStory = () => <CompleteExample />;
CompleteExampleStory.storyName = "Complete Example";

export const PerformanceAnalysisStory = () => <PerformanceAnalysis />;
PerformanceAnalysisStory.storyName = "Performance Analysis";


