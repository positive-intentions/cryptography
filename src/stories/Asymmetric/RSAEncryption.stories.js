import React, { useState } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
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
  Divider,
  Alert,
  Step,
  StepLabel,
  Stepper,
  Grid,
  Paper,
  Chip,
  VpnKey,
  Lock,
  LockOpen,
  Person,
  Share,
  SecurityIcon as Security
} from 'ui';

export default {
  title: 'Cryptography/Asymmetric/RSA Encryption',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'RSA public-key cryptography for secure message exchange between parties.',
      },
    },
  },
};

const RSAKeyGenerationDemo = () => {
  const { generateKeyPair, deserializePublicKey, deserializePrivateKey } = useCryptography();
  const [keyPair, setKeyPair] = useState(null);
  const [loading, setLoading] = useState(false);
  const [generationTime, setGenerationTime] = useState(null);

  const generateKeys = async () => {
    setLoading(true);
    const startTime = performance.now();
    
    try {
      const keys = await generateKeyPair();
      const endTime = performance.now();
      
      setKeyPair(keys);
      setGenerationTime((endTime - startTime).toFixed(2));
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="RSA Key Pair Generation"
      description="Generate a 4096-bit RSA key pair for asymmetric encryption."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          RSA key generation creates a mathematically linked pair of keys. The public key can be shared 
          openly, while the private key must be kept secure. Anyone can use the public key to encrypt 
          messages that only the private key holder can decrypt.
        </Alert>

        <Button
          variant="contained"
          onClick={generateKeys}
          disabled={loading}
          startIcon={<VpnKey />}
          size="large"
        >
          Generate 4096-bit RSA Key Pair
        </Button>

        <OperationStatus loading={loading} />

        {keyPair && (
          <Stack spacing={2}>
            <Box display="flex" alignItems="center" gap={2}>
              <Chip 
                label={`Generated in ${generationTime}ms`} 
                color="success" 
                variant="outlined"
                icon={<Security />}
              />
              <Typography variant="body2" color="text.secondary">
                Key size: 4096 bits | Algorithm: RSA-OAEP
              </Typography>
            </Box>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom color="success.main">
                    Public Key (Safe to Share)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Used by others to encrypt messages for you
                  </Typography>
                  <CodeDisplay
                    code={keyPair.publicKey ? JSON.stringify(keyPair.publicKey, null, 2) : 'No public key available'}
                    label="Public Key (JWK Format)"
                    maxHeight="200px"
                  />
                </Paper>
              </Grid>

              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom color="error.main">
                    Private Key (Keep Secret!)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Used to decrypt messages encrypted with your public key
                  </Typography>
                  <CodeDisplay
                    code={keyPair.privateKey ? JSON.stringify(keyPair.privateKey, null, 2) : 'No private key available'}
                    label="Private Key (JWK Format)"
                    secret={true}
                    maxHeight="200px"
                  />
                </Paper>
              </Grid>
            </Grid>
          </Stack>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const KeyGeneration = () => (
  <CryptographyProvider>
    <RSAKeyGenerationDemo />
  </CryptographyProvider>
);

const RSAEncryptionDemo = () => {
  const { 
    generateKeyPair, 
    deserializePublicKey, 
    deserializePrivateKey,
    encrypt,
    decrypt
  } = useCryptography();
  
  const [step, setStep] = useState(0);
  const [alice, setAlice] = useState({ keyPair: null, message: '', encrypted: '' });
  const [bob, setBob] = useState({ keyPair: null, message: '', decrypted: '' });
  const [loading, setLoading] = useState(false);

  const steps = [
    'Generate key pairs for Alice and Bob',
    'Alice encrypts message with Bob\'s public key',
    'Bob decrypts message with his private key'
  ];

  const generateKeysForBoth = async () => {
    setLoading(true);
    try {
      const [aliceKeys, bobKeys] = await Promise.all([
        generateKeyPair(),
        generateKeyPair()
      ]);
      
      setAlice(prev => ({ ...prev, keyPair: aliceKeys }));
      setBob(prev => ({ ...prev, keyPair: bobKeys }));
      setStep(1);
    } catch (error) {
      setLoading(false);
    }
  };

  const encryptMessage = async () => {
    if (!alice.message || !bob.keyPair) return;
    
    setLoading(true);
    try {
      const bobPublicKey = await deserializePublicKey(bob.keyPair.publicKey);
      const encrypted = await encrypt(alice.message, bobPublicKey);
      
      setAlice(prev => ({ ...prev, encrypted }));
      setStep(2);
    } catch (error) {
      setLoading(false);
    }
  };

  const decryptMessage = async () => {
    if (!alice.encrypted || !bob.keyPair) return;
    
    setLoading(true);
    try {
      const bobPrivateKey = await deserializePrivateKey(bob.keyPair.privateKey);
      const decrypted = await decrypt(alice.encrypted, bobPrivateKey);
      
      setBob(prev => ({ ...prev, decrypted }));
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Alice & Bob Encryption Scenario"
      description="A classic demonstration of how RSA public-key cryptography enables secure communication."
    >
      <Stack spacing={3}>
        <Stepper activeStep={step} alternativeLabel>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        <OperationStatus loading={loading} />

        {/* Step 1: Key Generation */}
        {step === 0 && (
          <Card>
            <CardHeader
              title="Step 1: Generate Key Pairs"
              subheader="Each party needs their own RSA key pair"
            />
            <CardContent>
              <Button
                variant="contained"
                onClick={generateKeysForBoth}
                disabled={loading}
                startIcon={<VpnKey />}
              >
                Generate Keys for Alice & Bob
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 2: Encryption */}
        {step === 1 && alice.keyPair && bob.keyPair && (
          <Card>
            <CardHeader
              title="Step 2: Alice Encrypts Message"
              subheader="Using Bob's public key to encrypt a message only Bob can read"
            />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Alice's Secret Message"
                  value={alice.message}
                  onChange={(e) => setAlice(prev => ({ ...prev, message: e.target.value }))}
                  multiline
                  rows={3}
                  fullWidth
                  placeholder="Enter message to encrypt..."
                />
                
                <Button
                  variant="contained"
                  onClick={encryptMessage}
                  disabled={loading || !alice.message}
                  startIcon={<Lock />}
                >
                  Encrypt with Bob's Public Key
                </Button>

                {alice.encrypted && (
                  <CodeDisplay
                    code={alice.encrypted}
                    label="Encrypted Message (Only Bob can decrypt this)"
                  />
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Step 3: Decryption */}
        {step === 2 && alice.encrypted && (
          <Card>
            <CardHeader
              title="Step 3: Bob Decrypts Message"
              subheader="Using his private key to decrypt Alice's message"
            />
            <CardContent>
              <Stack spacing={2}>
                <Button
                  variant="contained"
                  onClick={decryptMessage}
                  disabled={loading}
                  startIcon={<LockOpen />}
                >
                  Decrypt with Bob's Private Key
                </Button>

                {bob.decrypted && (
                  <Alert severity="success">
                    <Typography variant="h6" gutterBottom>
                      Message Successfully Decrypted!
                    </Typography>
                    <Typography variant="body1">
                      Original: "{alice.message}"
                    </Typography>
                    <Typography variant="body1">
                      Decrypted: "{bob.decrypted}"
                    </Typography>
                  </Alert>
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Key Information Display */}
        {alice.keyPair && bob.keyPair && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <Person color="primary" />
                  <Typography variant="h6">Alice's Keys</Typography>
                </Stack>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Alice shares her public key but keeps her private key secret
                </Typography>
                <CodeDisplay
                  code={alice.keyPair?.publicKey ? JSON.stringify(alice.keyPair.publicKey, null, 2) : 'No public key available'}
                  label="Alice's Public Key"
                  maxHeight="150px"
                />
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <Person color="secondary" />
                  <Typography variant="h6">Bob's Keys</Typography>
                </Stack>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Bob shares his public key but keeps his private key secret
                </Typography>
                <CodeDisplay
                  code={bob.keyPair?.publicKey ? JSON.stringify(bob.keyPair.publicKey, null, 2) : 'No public key available'}
                  label="Bob's Public Key"
                  maxHeight="150px"
                />
              </Paper>
            </Grid>
          </Grid>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const AliceAndBob = () => (
  <CryptographyProvider>
    <RSAEncryptionDemo />
  </CryptographyProvider>
);

const RSALimitationsDemo = () => {
  const { generateKeyPair, deserializePublicKey, encrypt } = useCryptography();
  const [keyPair, setKeyPair] = useState(null);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const generateKeys = async () => {
    setLoading(true);
    try {
      const keys = await generateKeyPair();
      setKeyPair(keys);
    } catch (error) {
      setLoading(false);
    }
  };

  const testEncryption = async () => {
    if (!keyPair || !message) return;
    
    setLoading(true);
    try {
      const publicKey = await deserializePublicKey(keyPair.publicKey);
      const encrypted = await encrypt(message, publicKey);
      setResult({ success: true, encrypted });
    } catch (error) {
      setResult({ success: false, error: error.message });
    } finally {
      setLoading(false);
    }
  };

  const maxMessageLength = 446; // RSA-OAEP with 4096-bit key

  return (
    <CryptoDemo
      title="RSA Limitations & Best Practices"
      description="Understanding the constraints and proper use cases for RSA encryption."
    >
      <Stack spacing={3}>
        <Alert severity="warning">
          <Typography variant="body2" gutterBottom>
            <strong>RSA Message Size Limit:</strong> RSA can only encrypt messages up to 
            (key_size_in_bits/8) - 2*hash_length - 2 bytes. For 4096-bit keys with SHA-256, 
            this is approximately 446 bytes.
          </Typography>
        </Alert>

        {!keyPair && (
          <Button
            variant="contained"
            onClick={generateKeys}
            disabled={loading}
            startIcon={<VpnKey />}
          >
            Generate Test Keys
          </Button>
        )}

        {keyPair && (
          <Stack spacing={2}>
            <TextField
              label="Test Message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              multiline
              rows={4}
              fullWidth
              variant="outlined"
              placeholder="Try entering a very long message..."
              error={message.length > maxMessageLength}
              helperText={
                message.length > maxMessageLength 
                  ? `Message too long! ${message.length}/${maxMessageLength} bytes`
                  : `${message.length}/${maxMessageLength} bytes`
              }
            />

            <Button
              variant="contained"
              onClick={testEncryption}
              disabled={loading || !message}
              startIcon={<Lock />}
              color={message.length > maxMessageLength ? "error" : "primary"}
            >
              Test Encryption
            </Button>

            {result && (
              <Box>
                {result.success ? (
                  <Alert severity="success">
                    <Typography variant="body2">
                      Encryption successful! Message length: {message.length} bytes
                    </Typography>
                  </Alert>
                ) : (
                  <Alert severity="error">
                    <Typography variant="body2">
                      Encryption failed: {result.error}
                    </Typography>
                  </Alert>
                )}
              </Box>
            )}
          </Stack>
        )}

        <Divider />

        <Box>
          <Typography variant="h6" gutterBottom>
            RSA Best Practices
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom color="success.main">
                  ✅ Good for RSA
                </Typography>
                <Typography component="ul" variant="body2" color="text.secondary">
                  <li>Encrypting small messages (under 446 bytes)</li>
                  <li>Digital signatures</li>
                  <li>Key exchange protocols</li>
                  <li>Encrypting symmetric keys</li>
                  <li>Authentication tokens</li>
                </Typography>
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom color="error.main">
                  ❌ Not ideal for RSA
                </Typography>
                <Typography component="ul" variant="body2" color="text.secondary">
                  <li>Large files or documents</li>
                  <li>Real-time streaming data</li>
                  <li>Bulk data encryption</li>
                  <li>High-frequency operations</li>
                  <li>Mobile/low-power devices</li>
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Hybrid Approach:</strong> In practice, RSA is often combined with 
              symmetric encryption (like AES). RSA encrypts a randomly generated AES key, 
              then AES encrypts the actual data. This gives you the security of RSA with 
              the efficiency of AES.
            </Typography>
          </Alert>
        </Box>
      </Stack>
    </CryptoDemo>
  );
};

export const RSALimitations = () => (
  <CryptographyProvider>
    <RSALimitationsDemo />
  </CryptographyProvider>
);