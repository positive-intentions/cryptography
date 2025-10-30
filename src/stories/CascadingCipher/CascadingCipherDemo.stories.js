/**
 * Cascading Cipher Interactive Demo
 *
 * Demonstrates the cascading cipher system with multiple encryption layers.
 * Shows how to daisy-chain MLS, Signal, DH, and AES encryption algorithms.
 */

import React, { useState } from 'react';
import {
  CascadingCipherManager,
  AESCipherLayer,
  DHCipherLayer,
} from '../../crypto/CascadingCipher';
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
  Switch,
  FormControlLabel,
} from 'ui';

export default {
  title: 'Cascading Cipher/Interactive Demo',
  parameters: {
    layout: 'fullscreen',
  },
};

const CascadingCipherDemo = () => {
  const [message, setMessage] = useState('Hello, Cascading Cipher!');
  const [password1, setPassword1] = useState('password-layer-1');
  const [password2, setPassword2] = useState('password-layer-2');
  const [password3, setPassword3] = useState('password-layer-3');

  const [useDH, setUseDH] = useState(true);
  const [dhKeyPair, setDhKeyPair] = useState(null);
  const [dhPublicKey, setDhPublicKey] = useState(null);

  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState('');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [processing, setProcessing] = useState(false);

  const addLog = (msg, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time: timestamp, message: msg, type }]);
  };

  // Generate DH key pair
  const generateDHKeys = async () => {
    try {
      addLog('🔑 Generating Diffie-Hellman key pair...', 'info');

      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      );

      // Export public key
      const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

      setDhKeyPair(keyPair);
      setDhPublicKey(new Uint8Array(publicKeyRaw));

      addLog('✅ DH key pair generated', 'success');
      addLog(`📤 Public key: ${Array.from(new Uint8Array(publicKeyRaw).slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}...`, 'info');
    } catch (err) {
      setError(`DH key generation failed: ${err.message}`);
      addLog(`❌ ${err.message}`, 'error');
    }
  };

  // Encrypt with cascading layers
  const handleEncrypt = async () => {
    setProcessing(true);
    setError(null);
    setLogs([]);

    try {
      addLog('🔒 Starting cascading encryption...', 'info');

      // Create cascading cipher manager
      const manager = new CascadingCipherManager();

      // Add layers based on configuration
      if (useDH) {
        if (!dhKeyPair) {
          throw new Error('DH keys not generated. Click "Generate DH Keys" first.');
        }
        const dhLayer = new DHCipherLayer();
        manager.addLayer(dhLayer);
        addLog('✅ Added DH-AES-GCM layer', 'success');
      }

      // Add AES layers
      const aesLayer1 = new AESCipherLayer();
      Object.defineProperty(aesLayer1, 'name', { value: 'AES-Layer-1' });
      manager.addLayer(aesLayer1);
      addLog('✅ Added AES Layer 1', 'success');

      const aesLayer2 = new AESCipherLayer();
      Object.defineProperty(aesLayer2, 'name', { value: 'AES-Layer-2' });
      manager.addLayer(aesLayer2);
      addLog('✅ Added AES Layer 2', 'success');

      const aesLayer3 = new AESCipherLayer();
      Object.defineProperty(aesLayer3, 'name', { value: 'AES-Layer-3' });
      manager.addLayer(aesLayer3);
      addLog('✅ Added AES Layer 3', 'success');

      addLog(`📊 Total layers: ${manager.layerCount}`, 'info');

      // Prepare keys
      const keys = {
        'AES-Layer-1': { password: password1 },
        'AES-Layer-2': { password: password2 },
        'AES-Layer-3': { password: password3 },
      };

      if (useDH) {
        // For DH, use same key pair (simulating key exchange with self)
        keys['DH-AES-GCM'] = {
          privateKey: dhKeyPair.privateKey,
          publicKey: dhKeyPair.publicKey,
        };
      }

      // Encrypt
      const plaintext = new TextEncoder().encode(message);
      addLog(`📝 Original size: ${plaintext.length} bytes`, 'info');

      const result = await manager.encrypt(plaintext, keys);

      addLog(`🔐 Encrypted size: ${result.finalSize} bytes`, 'info');
      addLog(`⏱️ Total time: ${result.totalProcessingTime.toFixed(2)}ms`, 'info');
      addLog('📊 Layer breakdown:', 'info');

      result.layers.forEach((layer, i) => {
        addLog(
          `  ${i + 1}. ${layer.algorithm}: ${layer.inputSize}B → ${layer.outputSize}B (${layer.processingTime.toFixed(2)}ms)`,
          'info'
        );
      });

      setEncrypted(result);
      addLog('✅ Encryption complete!', 'success');
    } catch (err) {
      console.error('Encryption error:', err);
      setError(`Encryption failed: ${err.message}`);
      addLog(`❌ ${err.message}`, 'error');
    } finally {
      setProcessing(false);
    }
  };

  // Decrypt cascaded payload
  const handleDecrypt = async () => {
    if (!encrypted) {
      setError('No encrypted data. Encrypt first!');
      return;
    }

    setProcessing(true);
    setError(null);

    try {
      addLog('🔓 Starting cascading decryption...', 'info');

      // Create manager with same layers
      const manager = new CascadingCipherManager();

      if (useDH) {
        const dhLayer = new DHCipherLayer();
        manager.addLayer(dhLayer);
      }

      const aesLayer1 = new AESCipherLayer();
      Object.defineProperty(aesLayer1, 'name', { value: 'AES-Layer-1' });
      manager.addLayer(aesLayer1);

      const aesLayer2 = new AESCipherLayer();
      Object.defineProperty(aesLayer2, 'name', { value: 'AES-Layer-2' });
      manager.addLayer(aesLayer2);

      const aesLayer3 = new AESCipherLayer();
      Object.defineProperty(aesLayer3, 'name', { value: 'AES-Layer-3' });
      manager.addLayer(aesLayer3);

      // Prepare keys
      const keys = {
        'AES-Layer-1': { password: password1 },
        'AES-Layer-2': { password: password2 },
        'AES-Layer-3': { password: password3 },
      };

      if (useDH) {
        keys['DH-AES-GCM'] = {
          privateKey: dhKeyPair.privateKey,
          publicKey: dhKeyPair.publicKey,
        };
      }

      // Decrypt (layers applied in reverse)
      const plaintextBytes = await manager.decrypt(encrypted, keys);
      const plaintextStr = new TextDecoder().decode(plaintextBytes);

      setDecrypted(plaintextStr);
      addLog('✅ Decryption complete!', 'success');
      addLog(`📝 Recovered message: "${plaintextStr}"`, 'success');
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
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h3" gutterBottom>
        🔐 Cascading Cipher Demo
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Interactive demonstration of daisy-chained encryption layers.
        Configure multiple cipher layers and watch data cascade through each encryption algorithm.
      </Typography>

      <Stack spacing={3}>
        {/* Configuration */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Configuration
            </Typography>

            <Box sx={{ mb: 2 }}>
              <FormControlLabel
                control={<Switch checked={useDH} onChange={(e) => setUseDH(e.target.checked)} />}
                label="Include Diffie-Hellman Layer"
              />
            </Box>

            {useDH && (
              <Box sx={{ mb: 2 }}>
                <Button variant="outlined" onClick={generateDHKeys} disabled={processing}>
                  Generate DH Keys
                </Button>
                {dhPublicKey && (
                  <Chip
                    label="DH Keys Ready"
                    color="success"
                    size="small"
                    sx={{ ml: 2 }}
                  />
                )}
              </Box>
            )}

            <TextField
              fullWidth
              label="Message to Encrypt"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              margin="normal"
              multiline
              rows={2}
            />

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" gutterBottom>
              AES Layer Passwords
            </Typography>
            <TextField
              fullWidth
              label="Layer 1 Password"
              type="password"
              value={password1}
              onChange={(e) => setPassword1(e.target.value)}
              margin="normal"
              size="small"
            />
            <TextField
              fullWidth
              label="Layer 2 Password"
              type="password"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              margin="normal"
              size="small"
            />
            <TextField
              fullWidth
              label="Layer 3 Password"
              type="password"
              value={password3}
              onChange={(e) => setPassword3(e.target.value)}
              margin="normal"
              size="small"
            />
          </CardContent>
        </Card>

        {/* Actions */}
        <Paper sx={{ p: 2 }}>
          <Stack direction="row" spacing={2}>
            <Button
              variant="contained"
              color="primary"
              onClick={handleEncrypt}
              disabled={processing || (useDH && !dhKeyPair)}
            >
              🔒 Encrypt
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={handleDecrypt}
              disabled={processing || !encrypted}
            >
              🔓 Decrypt
            </Button>
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

        {/* Results */}
        {encrypted && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Encrypted Result
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Final ciphertext: {encrypted.finalSize} bytes
              </Typography>
              <Box
                sx={{
                  p: 2,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                  wordBreak: 'break-all',
                  maxHeight: 100,
                  overflow: 'auto',
                }}
              >
                {Array.from(encrypted.finalCiphertext.slice(0, 200))
                  .map(b => b.toString(16).padStart(2, '0'))
                  .join(' ')}
                {encrypted.finalCiphertext.length > 200 && '...'}
              </Box>

              <Typography variant="subtitle2" sx={{ mt: 2 }}>
                Layer Information:
              </Typography>
              <List dense>
                {encrypted.layers.map((layer, i) => (
                  <ListItem key={i}>
                    <ListItemText
                      primary={`${i + 1}. ${layer.algorithm}`}
                      secondary={`${layer.inputSize}B → ${layer.outputSize}B (${layer.processingTime.toFixed(2)}ms)`}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        )}

        {decrypted && (
          <Alert severity="success">
            <Typography variant="subtitle2">Decrypted Message:</Typography>
            <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
              {decrypted}
            </Typography>
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
                  No operations yet. Click Encrypt to start.
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

export const Interactive = () => <CascadingCipherDemo />;

Interactive.storyName = 'Interactive Demo';
