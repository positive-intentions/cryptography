import React, { useState } from 'react';
import { Box, Typography, Button, Card, CardContent, TextField, Stepper, Step, StepLabel, 
         Alert, Accordion, AccordionSummary, AccordionDetails, Chip, Grid, Paper } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import KeyIcon from '@mui/icons-material/VpnKey';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from '../components/shared';

// Define the component first
const SignalProtocolDemo = () => {
  const crypto = useCryptography();
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const steps = [
    'Initialize Users',
    'Exchange Key Bundles',
    'Perform X3DH',
    'Verify Shared Secrets'
  ];

  const handleDemonstration = async () => {
    setLoading(true);
    setError('');
    setActiveStep(0);
    
    console.log('🚀 Starting Signal Protocol demonstration...');
    console.log('Crypto object available:', !!crypto);
    console.log('Available crypto methods:', crypto ? Object.keys(crypto).filter(k => k.startsWith('signal') || k.includes('Signal')) : 'None');
    
    try {
      // Step 1: Initialize Users
      console.log('📋 Step 1: Initializing users...');
      setActiveStep(0);
      const alice = await crypto.initializeSignalUser("Alice");
      console.log('✅ Alice initialized');
      const bob = await crypto.initializeSignalUser("Bob");
      console.log('✅ Bob initialized');
      
      await new Promise(resolve => setTimeout(resolve, 500)); // Demo delay
      setActiveStep(1);
      
      // Step 2: Get Bob's public key bundle
      const bobBundle = await crypto.getSignalPublicKeyBundle(bob);
      
      await new Promise(resolve => setTimeout(resolve, 500));
      setActiveStep(2);
      
      // Step 3: Perform X3DH key exchange
      const exchangeResult = await crypto.performSignalX3DHKeyExchange(alice, bobBundle);
      
      // Note: Don't consume the one-time prekey yet - Bob needs it to derive the shared secret
      
      await new Promise(resolve => setTimeout(resolve, 500));
      setActiveStep(3);
      
      // Step 4: Verify Bob can derive the same secret
      const aliceIdentityPublic = await crypto.exportSignalPublicKey(alice.identityKeyPair.publicKey);
      
      // Important: Bob needs to know which specific one-time prekey was used
      const usedOneTimePrekey = exchangeResult.usedOneTimePrekey ? bobBundle.oneTimePrekey : null;
      
      const bobSecret = await crypto.deriveSignalSharedSecret(
        bob,
        exchangeResult.aliceEphemeralPublic,
        aliceIdentityPublic,
        exchangeResult.usedOneTimePrekey,
        usedOneTimePrekey // Pass the actual prekey that was used
      );
      
      // Now consume the one-time prekey after both sides have used it
      if (exchangeResult.usedOneTimePrekey) {
        crypto.consumeSignalOneTimePrekey(bob);
      }
      
      // Convert to hex for comparison
      const aliceSecretHex = crypto.bufferToSignalHex(exchangeResult.masterSecret);
      const bobSecretHex = crypto.bufferToSignalHex(bobSecret);
      const success = aliceSecretHex === bobSecretHex;
      
      setResults({
        success,
        alice,
        bob,
        bobBundle,
        exchangeResult,
        aliceSecret: aliceSecretHex,
        bobSecret: bobSecretHex,
        aliceIdentityPublic: crypto.bufferToSignalHex(aliceIdentityPublic),
        bobIdentityPublic: crypto.bufferToSignalHex(bobBundle.identityKey),
        bobIdentitySigningPublic: crypto.bufferToSignalHex(bobBundle.identitySigningKey),
        ephemeralPublic: crypto.bufferToSignalHex(exchangeResult.aliceEphemeralPublic),
        usedOneTimePrekey: exchangeResult.usedOneTimePrekey
      });
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteDemo = async () => {
    setLoading(true);
    setError('');
    
    try {
      const demoResult = await crypto.demonstrateSignalProtocol();
      
      setResults({
        ...demoResult,
        aliceIdentityPublic: crypto.bufferToSignalHex(
          await crypto.exportSignalPublicKey(demoResult.alice.identityKeyPair.publicKey)
        ),
        bobIdentityPublic: crypto.bufferToSignalHex(
          await crypto.exportSignalPublicKey(demoResult.bob.identityKeyPair.publicKey)
        ),
        ephemeralPublic: crypto.bufferToSignalHex(demoResult.exchangeResult.aliceEphemeralPublic)
      });
      setActiveStep(4);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo title="Signal Protocol X3DH Key Exchange" icon={<SecurityIcon />}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="body1" paragraph>
          The Signal Protocol establishes secure communication between parties who may have never 
          communicated before. This demonstration shows the complete X3DH key exchange process.
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6}>
            <Button 
              variant="contained" 
              onClick={handleDemonstration}
              disabled={loading}
              fullWidth
              startIcon={<SwapHorizIcon />}
            >
              {loading ? 'Running X3DH...' : 'Step-by-Step Demo'}
            </Button>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Button 
              variant="outlined" 
              onClick={handleCompleteDemo}
              disabled={loading}
              fullWidth
              startIcon={<SecurityIcon />}
            >
              {loading ? 'Running...' : 'Complete Demo'}
            </Button>
          </Grid>
        </Grid>

        {loading && (
          <Box sx={{ mb: 2 }}>
            <Stepper activeStep={activeStep} alternativeLabel>
              {steps.map((label) => (
                <Step key={label}>
                  <StepLabel>{label}</StepLabel>
                </Step>
              ))}
            </Stepper>
          </Box>
        )}

        <OperationStatus 
          loading={loading} 
          error={error} 
          success={results?.success} 
        />
      </Box>

      {results && (
        <Box sx={{ mt: 3 }}>
          <Alert severity={results.success ? "success" : "error"} sx={{ mb: 3 }}>
            <Typography variant="h6">
              {results.success ? 
                "✅ X3DH Key Exchange Successful!" : 
                "❌ Key Exchange Failed"
              }
            </Typography>
            {results.success && (
              <Typography variant="body2">
                Both Alice and Bob derived the same shared secret. Secure communication established!
              </Typography>
            )}
          </Alert>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <KeyIcon /> Shared Secrets
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography variant="subtitle1" gutterBottom color="primary">
                        Alice's Derived Secret
                      </Typography>
                      <CodeDisplay 
                        code={results.aliceSecret} 
                        language="text"
                        maxHeight="100px"
                      />
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography variant="subtitle1" gutterBottom color="secondary">
                        Bob's Derived Secret
                      </Typography>
                      <CodeDisplay 
                        code={results.bobSecret} 
                        language="text"
                        maxHeight="100px"
                      />
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
              
              <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="body2">
                  Secrets Match:
                </Typography>
                <Chip 
                  label={results.success ? "YES" : "NO"} 
                  color={results.success ? "success" : "error"}
                  size="small"
                />
                {results.usedOneTimePrekey && (
                  <Chip 
                    label="One-time Prekey Used" 
                    color="info"
                    size="small"
                  />
                )}
              </Box>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Identity Keys</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Alice's Identity Key (Public)
                  </Typography>
                  <CodeDisplay 
                    code={results.aliceIdentityPublic} 
                    language="text"
                    maxHeight="80px"
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Bob's Identity Key (Public)
                  </Typography>
                  <CodeDisplay 
                    code={results.bobIdentityPublic} 
                    language="text"
                    maxHeight="80px"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Ephemeral Key</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="subtitle2" gutterBottom>
                Alice's Ephemeral Key (Public) - Generated for this session
              </Typography>
              <CodeDisplay 
                code={results.ephemeralPublic} 
                language="text"
                maxHeight="80px"
              />
              <Typography variant="body2" sx={{ mt: 1 }}>
                This key is generated fresh for each conversation and provides forward secrecy.
              </Typography>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Security Properties Achieved</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Chip 
                  icon={<SecurityIcon />}
                  label="Forward Secrecy: Past messages remain secure even if long-term keys are compromised"
                  color="success"
                  variant="outlined"
                />
                <Chip 
                  icon={<SecurityIcon />}
                  label="Future Secrecy: Current compromise doesn't affect future sessions"
                  color="success"
                  variant="outlined"
                />
                <Chip 
                  icon={<SecurityIcon />}
                  label="Mutual Authentication: Both parties verify each other's identity"
                  color="success"
                  variant="outlined"
                />
                {results.usedOneTimePrekey && (
                  <Chip 
                    icon={<SecurityIcon />}
                    label="Perfect Forward Secrecy: One-time prekeys ensure perfect forward secrecy"
                    color="success"
                    variant="outlined"
                  />
                )}
              </Box>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Implementation Details</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Cryptographic Operations Performed:</strong>
              </Typography>
              <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
                <li>
                  <strong>DH1:</strong> Alice_Identity × Bob_SignedPrekey (Mutual Authentication)
                </li>
                <li>
                  <strong>DH2:</strong> Alice_Ephemeral × Bob_Identity (Forward Secrecy)
                </li>
                <li>
                  <strong>DH3:</strong> Alice_Ephemeral × Bob_SignedPrekey (Additional Forward Secrecy)
                </li>
                {results.usedOneTimePrekey && (
                  <li>
                    <strong>DH4:</strong> Alice_Ephemeral × Bob_OneTimePrekey (Perfect Forward Secrecy)
                  </li>
                )}
              </Box>
              <Typography variant="body2" sx={{ mt: 2 }}>
                <strong>Key Derivation:</strong> All DH outputs are concatenated and processed through 
                HKDF-SHA256 with context "Signal_X3DH_Key_Derivation" to produce the final shared secret.
              </Typography>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}
    </CryptoDemo>
  );
};

export default {
  title: 'Signal Protocol/X3DH Key Exchange',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: `
# Signal Protocol X3DH Key Exchange

This demo showcases the Signal Protocol's X3DH (Extended Triple Diffie-Hellman) key exchange implementation. 
Signal Protocol is used by Signal, WhatsApp, and other messaging apps to establish secure communication channels.

## Security Properties Demonstrated:

- **Forward Secrecy**: Past messages remain secure even if long-term keys are compromised
- **Future Secrecy**: Current compromise doesn't affect future sessions  
- **Mutual Authentication**: Both parties verify each other's identity
- **Perfect Forward Secrecy**: One-time prekeys ensure perfect forward secrecy

## Key Components:

- **Identity Keys**: Long-term keys for user identification
- **Signed Prekeys**: Medium-term keys signed by identity key
- **One-time Prekeys**: Single-use keys for forward secrecy
- **Ephemeral Keys**: Session-specific keys generated per exchange

## Cryptographic Operations:

- **ECDH with P-256**: For key agreement (Signal uses Curve25519)
- **ECDSA with P-256**: For signing and verification
- **HKDF-SHA256**: For key derivation from shared secrets
        `
      }
    }
  }
};

// Default story
export const Default = () => (
  <CryptographyProvider>
    <SignalProtocolDemo />
  </CryptographyProvider>
);

// Story showing individual operations
const IndividualOperationsDemo = () => {
  const crypto = useCryptography();
  const [keyPair, setKeyPair] = useState(null);
  const [publicKeyHex, setPublicKeyHex] = useState('');
  const [signature, setSignature] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);

  const generateKeys = async () => {
    try {
      const signingKeyPair = await crypto.generateSignalSigningKeyPair();
      const dhKeyPair = await crypto.generateSignalKeyPair();
      
      setKeyPair({ signing: signingKeyPair, dh: dhKeyPair });
      
      const publicKeyBytes = await crypto.exportSignalPublicKey(signingKeyPair.publicKey);
      setPublicKeyHex(crypto.bufferToSignalHex(publicKeyBytes));
    } catch (error) {
      console.error('Key generation failed:', error);
    }
  };

  const signData = async () => {
    if (!keyPair) return;
    
    const data = new TextEncoder().encode("Hello Signal Protocol!");
    const sig = await crypto.signSignalData(keyPair.signing.privateKey, data);
    setSignature(crypto.bufferToSignalHex(sig));
  };

  const verifyData = async () => {
    if (!keyPair || !signature) return;
    
    const data = new TextEncoder().encode("Hello Signal Protocol!");
    const sigBytes = new Uint8Array(signature.match(/.{2}/g).map(byte => parseInt(byte, 16))).buffer;
    
    const isValid = await crypto.verifySignalSignature(
      keyPair.signing.publicKey, 
      sigBytes, 
      data
    );
    setVerificationResult(isValid);
  };

  return (
    <CryptoDemo title="Signal Protocol Individual Operations" icon={<KeyIcon />}>
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Key Generation
              </Typography>
              <Button 
                variant="contained" 
                onClick={generateKeys}
                fullWidth
                sx={{ mb: 2 }}
              >
                Generate Keys
              </Button>
              {publicKeyHex && (
                <Box>
                  <Typography variant="subtitle2">Public Key (Hex):</Typography>
                  <CodeDisplay 
                    code={publicKeyHex} 
                    language="text"
                    maxHeight="100px"
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Digital Signature
              </Typography>
              <Button 
                variant="contained" 
                onClick={signData}
                disabled={!keyPair}
                fullWidth
                sx={{ mb: 2 }}
              >
                Sign Data
              </Button>
              {signature && (
                <Box>
                  <Typography variant="subtitle2">Signature (Hex):</Typography>
                  <CodeDisplay 
                    code={signature} 
                    language="text"
                    maxHeight="100px"
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Signature Verification
              </Typography>
              <Button 
                variant="contained" 
                onClick={verifyData}
                disabled={!signature}
                fullWidth
                sx={{ mb: 2 }}
              >
                Verify Signature
              </Button>
              {verificationResult !== null && (
                <Box>
                  <Chip 
                    label={verificationResult ? "Valid Signature" : "Invalid Signature"}
                    color={verificationResult ? "success" : "error"}
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </CryptoDemo>
  );
};

export const IndividualOperations = () => (
  <CryptographyProvider>
    <IndividualOperationsDemo />
  </CryptographyProvider>
);

// Story for educational explanations
const EducationalGuideDemo = () => {
  return (
    <CryptoDemo title="Signal Protocol Educational Guide" icon={<SecurityIcon />}>
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">What is Signal Protocol?</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography paragraph>
            Signal Protocol is a cryptographic protocol that provides end-to-end encryption for messaging applications. 
            It's used by Signal, WhatsApp, Facebook Messenger's Secret Conversations, and Google's RCS messaging.
          </Typography>
          <Typography paragraph>
            The protocol consists of two main parts:
          </Typography>
          <Box component="ul" sx={{ pl: 2 }}>
            <li><strong>X3DH (Extended Triple Diffie-Hellman):</strong> Initial key agreement between parties</li>
            <li><strong>Double Ratchet:</strong> Ongoing message encryption with forward and backward secrecy</li>
          </Box>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Key Hierarchy</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Paper sx={{ p: 2, bgcolor: 'primary.light', color: 'primary.contrastText' }}>
              <Typography variant="h6">Identity Keys (Long-term)</Typography>
              <Typography variant="body2">
                Used for user identification and authentication. Generated once and stored securely.
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 2, bgcolor: 'secondary.light', color: 'secondary.contrastText' }}>
              <Typography variant="h6">Signed Prekeys (Medium-term)</Typography>
              <Typography variant="body2">
                Rotated periodically (weekly). Signed by identity key to prove authenticity.
                Enable asynchronous messaging.
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 2, bgcolor: 'success.light', color: 'success.contrastText' }}>
              <Typography variant="h6">One-time Prekeys (Single-use)</Typography>
              <Typography variant="body2">
                Generated in batches, consumed after single use. Provide perfect forward secrecy.
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 2, bgcolor: 'warning.light', color: 'warning.contrastText' }}>
              <Typography variant="h6">Ephemeral Keys (Session-specific)</Typography>
              <Typography variant="body2">
                Generated fresh for each conversation initiation. Never stored persistently.
              </Typography>
            </Paper>
          </Box>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Security Guarantees</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            <Alert severity="info">
              <Typography variant="subtitle2">Forward Secrecy</Typography>
              If your long-term keys are compromised, past messages remain secure because they were 
              encrypted with ephemeral keys that no longer exist.
            </Alert>
            
            <Alert severity="info">
              <Typography variant="subtitle2">Future Secrecy / Post-Compromise Security</Typography>
              If your current session is compromised, future sessions will be secure because new 
              ephemeral keys are generated for each session.
            </Alert>
            
            <Alert severity="success">
              <Typography variant="subtitle2">Mutual Authentication</Typography>
              Both parties can verify each other's identity through the identity key signatures.
            </Alert>
            
            <Alert severity="success">
              <Typography variant="subtitle2">Perfect Forward Secrecy</Typography>
              One-time prekeys ensure that each conversation has unique entropy that cannot be recreated.
            </Alert>
            
            <Alert severity="warning">
              <Typography variant="subtitle2">Deniability</Typography>
              Recipients cannot prove to third parties that a message came from the claimed sender 
              (this is a feature, not a bug).
            </Alert>
          </Box>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Real-World Usage</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography paragraph>
            <strong>Applications using Signal Protocol:</strong>
          </Typography>
          <Box component="ul" sx={{ pl: 2, mb: 2 }}>
            <li>Signal Messenger (original implementation)</li>
            <li>WhatsApp (billions of users)</li>
            <li>Facebook Messenger Secret Conversations</li>
            <li>Google RCS messaging</li>
            <li>Skype Private Conversations</li>
          </Box>
          
          <Typography paragraph>
            <strong>Why it matters:</strong>
          </Typography>
          <Typography variant="body2">
            Signal Protocol protects the private communications of billions of people worldwide. 
            Its security properties ensure that even if governments or hackers compromise servers 
            or devices, the content of messages remains private.
          </Typography>
        </AccordionDetails>
      </Accordion>
    </CryptoDemo>
  );
};

export const EducationalGuide = () => (
  <CryptographyProvider>
    <EducationalGuideDemo />
  </CryptographyProvider>
);