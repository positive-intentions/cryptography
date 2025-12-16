/**
 * ML-KEM (CRYSTALS-Kyber) Standalone Demo
 *
 * Interactive demonstration of ML-KEM quantum-resistant key encapsulation mechanism.
 * Shows key generation, encryption, decryption, and performance metrics.
 */

import React, { useState } from 'react';
import { MLKEMCipherLayer } from '../../crypto/CascadingCipher';
import { MlKem768 } from '@hpke/ml-kem';
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
} from 'ui';

export default {
  title: 'Cascading Cipher/ML-KEM Demo',
  parameters: {
    layout: 'fullscreen',
  },
};

const MLKEMDemo = () => {
  const [message, setMessage] = useState('Hello, Quantum-Resistant World!');
  const [keyPair, setKeyPair] = useState(null);
  const [publicKeyHex, setPublicKeyHex] = useState('');
  const [privateKeyHex, setPrivateKeyHex] = useState('');
  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState('');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [metrics, setMetrics] = useState(null);

  const addLog = (msg, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time: timestamp, message: msg, type }]);
  };

  // Generate ML-KEM key pair
  const generateKeys = async () => {
    setProcessing(true);
    setError(null);
    setLogs([]);
    setKeyPair(null);
    setPublicKeyHex('');
    setPrivateKeyHex('');
    setEncrypted(null);
    setDecrypted('');

    try {
      addLog('🔑 Generating ML-KEM-768 key pair...', 'info');
      const startTime = performance.now();

      const kem = new MlKem768();
      const pair = await kem.generateKeyPair();

      const endTime = performance.now();
      const keyGenTime = endTime - startTime;

      setKeyPair(pair);
      
      // Get key bytes
      const publicKeyBytes = pair.publicKey.key;
      const privateKeyBytes = pair.privateKey.key;

      // Display first 16 bytes as hex
      const pubHex = Array.from(publicKeyBytes.slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
      const privHex = Array.from(privateKeyBytes.slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      setPublicKeyHex(pubHex);
      setPrivateKeyHex(privHex);

      setMetrics({
        keyGenTime,
        publicKeySize: publicKeyBytes.length,
        privateKeySize: privateKeyBytes.length,
      });

      addLog(`✅ Key pair generated in ${keyGenTime.toFixed(2)}ms`, 'success');
      addLog(`📊 Public key size: ${publicKeyBytes.length} bytes`, 'info');
      addLog(`📊 Private key size: ${privateKeyBytes.length} bytes`, 'info');
      addLog(`📤 Public key (first 16 bytes): ${pubHex}...`, 'info');
    } catch (err) {
      console.error('Key generation error:', err);
      setError(`Key generation failed: ${err.message}`);
      addLog(`❌ ${err.message}`, 'error');
    } finally {
      setProcessing(false);
    }
  };

  // Encrypt with ML-KEM
  const handleEncrypt = async () => {
    if (!keyPair) {
      setError('Please generate keys first');
      return;
    }

    setProcessing(true);
    setError(null);
    setEncrypted(null);
    setDecrypted('');

    try {
      addLog('🔒 Starting ML-KEM encryption...', 'info');
      const startTime = performance.now();

      const layer = new MLKEMCipherLayer();
      const plaintext = new TextEncoder().encode(message);

      addLog(`📝 Plaintext size: ${plaintext.length} bytes`, 'info');

      const result = await layer.encrypt(plaintext, {
        publicKey: keyPair.publicKey,
      });

      const endTime = performance.now();
      const encryptTime = endTime - startTime;

      setEncrypted(result);
      
      if (metrics) {
        setMetrics({
          ...metrics,
          encryptTime,
          encapsulatedSize: result.parameters.encapsulated.length,
          ciphertextSize: result.ciphertext.length,
        });
      }

      addLog(`✅ Encryption complete in ${encryptTime.toFixed(2)}ms`, 'success');
      addLog(`📊 Encapsulated key size: ${result.parameters.encapsulated.length} bytes`, 'info');
      addLog(`📊 Ciphertext size: ${result.ciphertext.length} bytes`, 'info');
      addLog(`📈 Size overhead: ${((result.ciphertext.length / plaintext.length - 1) * 100).toFixed(1)}%`, 'info');
    } catch (err) {
      console.error('Encryption error:', err);
      setError(`Encryption failed: ${err.message}`);
      addLog(`❌ ${err.message}`, 'error');
    } finally {
      setProcessing(false);
    }
  };

  // Decrypt with ML-KEM
  const handleDecrypt = async () => {
    if (!encrypted || !keyPair) {
      setError('Please encrypt data first');
      return;
    }

    setProcessing(true);
    setError(null);

    try {
      addLog('🔓 Starting ML-KEM decryption...', 'info');
      const startTime = performance.now();

      const layer = new MLKEMCipherLayer();
      const plaintextBytes = await layer.decrypt(encrypted, {
        privateKey: keyPair.privateKey,
      });

      const endTime = performance.now();
      const decryptTime = endTime - startTime;

      const plaintextStr = new TextDecoder().decode(plaintextBytes);
      setDecrypted(plaintextStr);

      if (metrics) {
        setMetrics({
          ...metrics,
          decryptTime,
        });
      }

      addLog(`✅ Decryption complete in ${decryptTime.toFixed(2)}ms`, 'success');
      addLog(`📝 Recovered message: "${plaintextStr}"`, 'success');

      if (plaintextStr === message) {
        addLog('🎉 Round-trip successful! Message matches perfectly!', 'success');
      } else {
        addLog('⚠️ Warning: Decrypted message does not match original', 'error');
      }
    } catch (err) {
      console.error('Decryption error:', err);
      setError(`Decryption failed: ${err.message}`);
      addLog(`❌ ${err.message}`, 'error');
    } finally {
      setProcessing(false);
    }
  };

  const reset = () => {
    setEncrypted(null);
    setDecrypted('');
    setLogs([]);
    setError(null);
    setMetrics(null);
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h3" gutterBottom>
        🔐 ML-KEM (CRYSTALS-Kyber) Demo
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Interactive demonstration of ML-KEM-768, a NIST-standardized quantum-resistant key encapsulation mechanism.
        ML-KEM provides post-quantum security equivalent to AES-192.
      </Typography>

      <Stack spacing={3}>
        {/* Key Generation */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Step 1: Generate Key Pair
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              ML-KEM uses a key encapsulation mechanism (KEM) where the public key is used for encryption
              and the private key is used for decryption.
            </Typography>

            <Button
              variant="contained"
              onClick={generateKeys}
              disabled={processing}
              sx={{ mb: 2 }}
            >
              Generate ML-KEM Key Pair
            </Button>

            {keyPair && (
              <Box sx={{ mt: 2 }}>
                <Alert severity="success" sx={{ mb: 2 }}>
                  ✅ Key pair generated successfully
                </Alert>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Public Key (first 16 bytes):
                    </Typography>
                    <Box
                      sx={{
                        p: 1,
                        bgcolor: 'grey.100',
                        borderRadius: 1,
                        fontFamily: 'monospace',
                        fontSize: '0.875rem',
                        wordBreak: 'break-all',
                      }}
                    >
                      {publicKeyHex}...
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                      Full size: {metrics?.publicKeySize} bytes
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Private Key (first 16 bytes):
                    </Typography>
                    <Box
                      sx={{
                        p: 1,
                        bgcolor: 'grey.100',
                        borderRadius: 1,
                        fontFamily: 'monospace',
                        fontSize: '0.875rem',
                        wordBreak: 'break-all',
                      }}
                    >
                      {privateKeyHex}...
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                      Full size: {metrics?.privateKeySize} bytes
                    </Typography>
                  </Grid>
                </Grid>
              </Box>
            )}
          </CardContent>
        </Card>

        {/* Encryption */}
        {keyPair && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Step 2: Encrypt Message
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Encrypt a message using the public key. ML-KEM encapsulates a shared secret,
                which is then used with AES-GCM for authenticated encryption.
              </Typography>

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
                color="primary"
                onClick={handleEncrypt}
                disabled={processing || !message}
                sx={{ mt: 2 }}
              >
                🔒 Encrypt with Public Key
              </Button>

              {encrypted && (
                <Box sx={{ mt: 3 }}>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    ✅ Message encrypted successfully
                  </Alert>
                  <Typography variant="subtitle2" gutterBottom>
                    Encapsulated Key (first 32 bytes):
                  </Typography>
                  <Box
                    sx={{
                      p: 1,
                      bgcolor: 'grey.100',
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.75rem',
                      wordBreak: 'break-all',
                      maxHeight: 60,
                      overflow: 'auto',
                    }}
                  >
                    {Array.from(encrypted.parameters.encapsulated.slice(0, 32))
                      .map(b => b.toString(16).padStart(2, '0'))
                      .join(' ')}...
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                    Full encapsulated key: {encrypted.parameters.encapsulated.length} bytes
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        )}

        {/* Decryption */}
        {encrypted && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Step 3: Decrypt Message
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Decrypt the message using the private key. ML-KEM decapsulates the shared secret,
                which is then used to decrypt the AES-GCM ciphertext.
              </Typography>

              <Button
                variant="contained"
                color="secondary"
                onClick={handleDecrypt}
                disabled={processing}
              >
                🔓 Decrypt with Private Key
              </Button>

              {decrypted && (
                <Alert severity="success" sx={{ mt: 2 }}>
                  <Typography variant="subtitle2">Decrypted Message:</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold', mt: 1 }}>
                    {decrypted}
                  </Typography>
                  {decrypted === message && (
                    <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                      ✅ Perfect match! Round-trip successful.
                    </Typography>
                  )}
                </Alert>
              )}
            </CardContent>
          </Card>
        )}

        {/* Performance Metrics */}
        {metrics && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Performance Metrics
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Key Generation Time"
                    secondary={`${metrics.keyGenTime?.toFixed(2)}ms`}
                  />
                </ListItem>
                {metrics.encryptTime && (
                  <ListItem>
                    <ListItemText
                      primary="Encryption Time"
                      secondary={`${metrics.encryptTime.toFixed(2)}ms`}
                    />
                  </ListItem>
                )}
                {metrics.decryptTime && (
                  <ListItem>
                    <ListItemText
                      primary="Decryption Time"
                      secondary={`${metrics.decryptTime.toFixed(2)}ms`}
                    />
                  </ListItem>
                )}
                <ListItem>
                  <ListItemText
                    primary="Public Key Size"
                    secondary={`${metrics.publicKeySize} bytes (${(metrics.publicKeySize / 1024).toFixed(2)} KB)`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Private Key Size"
                    secondary={`${metrics.privateKeySize} bytes (${(metrics.privateKeySize / 1024).toFixed(2)} KB)`}
                  />
                </ListItem>
                {metrics.encapsulatedSize && (
                  <ListItem>
                    <ListItemText
                      primary="Encapsulated Key Size"
                      secondary={`${metrics.encapsulatedSize} bytes`}
                    />
                  </ListItem>
                )}
                {metrics.ciphertextSize && (
                  <ListItem>
                    <ListItemText
                      primary="Ciphertext Size"
                      secondary={`${metrics.ciphertextSize} bytes`}
                    />
                  </ListItem>
                )}
              </List>
            </CardContent>
          </Card>
        )}

        {/* Algorithm Information */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              About ML-KEM-768
            </Typography>
            <List dense>
              <ListItem>
                <ListItemText
                  primary="Algorithm"
                  secondary="ML-KEM (formerly CRYSTALS-Kyber)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Security Level"
                  secondary="NIST Level 3 (equivalent to AES-192)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Quantum Resistance"
                  secondary="Yes - Resistant to attacks from quantum computers"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Standard"
                  secondary="NIST PQC Standard (FIPS 203)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Key Encapsulation"
                  secondary="Public key encrypts, private key decrypts"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Symmetric Encryption"
                  secondary="AES-GCM-256 (derived from encapsulated shared secret)"
                />
              </ListItem>
            </List>
          </CardContent>
        </Card>

        {/* Actions */}
        <Paper sx={{ p: 2 }}>
          <Stack direction="row" spacing={2}>
            <Button variant="outlined" onClick={reset} disabled={processing}>
              Reset
            </Button>
          </Stack>
        </Paper>

        {/* Error Display */}
        {error && (
          <Alert severity="error" onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {/* Logs */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Operation Log
            </Typography>
            <Box
              sx={{
                maxHeight: 300,
                overflow: 'auto',
                bgcolor: 'grey.50',
                p: 2,
                borderRadius: 1,
              }}
            >
              {logs.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No operations yet. Click "Generate ML-KEM Key Pair" to start.
                </Typography>
              ) : (
                logs.map((log, i) => (
                  <Typography
                    key={i}
                    variant="body2"
                    sx={{
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      color: log.type === 'error' ? 'error.main' : log.type === 'success' ? 'success.main' : 'text.primary',
                    }}
                  >
                    [{log.time}] {log.message}
                  </Typography>
                ))
              )}
            </Box>
          </CardContent>
        </Card>
      </Stack>
    </Container>
  );
};

export const MLKEMStandalone = () => <MLKEMDemo />;

MLKEMStandalone.storyName = 'ML-KEM Standalone Demo';

