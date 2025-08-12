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
    <CryptoDemo title="Signal Protocol Educational Guide - ELI5 Edition" icon={<SecurityIcon />}>
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🎯 What is Signal Protocol? (Explained Like You're 5)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="h6" gutterBottom>
              📱 Imagine You Want to Send a Secret Note to Your Friend
            </Typography>
          </Alert>
          
          <Typography paragraph>
            Think of Signal Protocol like a <strong>magical lockbox system</strong> for sending secret messages to your friends. 
            When you want to send a message to your friend Bob, you need to make sure that:
          </Typography>
          
          <Box component="ul" sx={{ pl: 2, mb: 2, '& li': { mb: 1 } }}>
            <li>🔒 <strong>Only Bob can read it</strong> (not even the mail carrier can peek!)</li>
            <li>🔑 <strong>You and Bob never need to meet in person</strong> to exchange keys</li>
            <li>⏰ <strong>Old messages stay secret</strong> even if someone steals your keys later</li>
            <li>🔄 <strong>Each message uses a new lock</strong> so breaking one doesn't break others</li>
          </Box>

          <Paper sx={{ p: 2, bgcolor: 'grey.100', mb: 2 }}>
            <Typography variant="h6" gutterBottom color="primary">
              🏗️ The Two Main Parts:
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      1. X3DH (The First Handshake) 🤝
                    </Typography>
                    <Typography variant="body2">
                      This is like exchanging special decoder rings when you first become friends. 
                      It happens once when Alice and Bob first start talking.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      2. Double Ratchet (Ongoing Chat) 🔄
                    </Typography>
                    <Typography variant="body2">
                      After the handshake, this creates new keys for every single message, 
                      like having a new padlock for each letter you send.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          <Alert severity="success">
            <Typography variant="body2">
              <strong>Fun Fact:</strong> This is the same technology that protects messages for 
              <strong> billions of people</strong> on WhatsApp, Signal, and other apps every day!
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🔑 The Four Types of Keys (Think of Them as Different Locks)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>Key Insight:</strong> Signal Protocol uses multiple types of keys because 
              <strong> no single key can provide all the security properties we need</strong>. 
              It's like having different keys for different purposes in real life!
            </Typography>
          </Alert>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Paper sx={{ p: 3, bgcolor: 'primary.light', color: 'primary.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>1. 🏠 Identity Keys (Your House Key)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What they do:</strong> These are like your house key - they identify who you are and last a long time.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why we need them:</strong> Bob needs to know messages actually come from Alice (authentication).
              </Typography>
              <CodeDisplay 
                code={`// JavaScript: How to generate identity keys
const identityKeyPair = await crypto.generateSignalSigningKeyPair();

// This creates two keys:
// - Private key: Only Alice keeps this (like keeping house key secret)
// - Public key: Alice shares this with everyone (like her address)

console.log("Alice's identity established!");`}
                language="javascript"
                maxHeight="150px"
              />
              <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                🔐 Uses ECDSA with P-256 curve for digital signatures (industry standard, used by Bitcoin & TLS)
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 3, bgcolor: 'secondary.light', color: 'secondary.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>2. 📝 Signed Prekeys (Your Office Badge)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What they do:</strong> Like an office badge that gets renewed weekly - proves you belong here.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why we need them:</strong> Allows messaging even when you're offline (asynchronous communication).
              </Typography>
              <CodeDisplay 
                code={`// JavaScript: How Bob creates signed prekeys
const signedPrekeyPair = await crypto.generateSignalKeyPair();

// Bob signs this prekey with his identity key to prove it's really his
const signature = await crypto.signSignalData(
  bob.identityKeyPair.privateKey,  // Bob's house key signs it
  signedPrekeyPair.publicKey       // The office badge
);

// Bob uploads this to the server so Alice can find it later
const bobBundle = {
  identityKey: bob.identityKeyPair.publicKey,
  signedPrekey: signedPrekeyPair.publicKey,
  signature: signature
};`}
                language="javascript"
                maxHeight="200px"
              />
              <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                🔐 Uses ECDH with P-256 curve for key agreement (mathematically secure shared secrets)
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 3, bgcolor: 'success.light', color: 'success.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>3. 🎫 One-time Prekeys (Concert Tickets)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What they do:</strong> Like concert tickets - use once and throw away.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why we need them:</strong> Even if someone steals all your other keys later, 
                this conversation stays secret forever (perfect forward secrecy).
              </Typography>
              <CodeDisplay 
                code={`// JavaScript: How Bob creates one-time prekeys
const oneTimePrekeys = [];

// Bob generates many tickets in advance
for (let i = 0; i < 100; i++) {
  const prekeyPair = await crypto.generateSignalKeyPair();
  oneTimePrekeys.push(prekeyPair);
}

// Each prekey gets used exactly once
console.log("Bob created 100 one-time tickets");

// When Alice wants to message Bob:
const usedPrekey = oneTimePrekeys.pop(); // Take one ticket
// This ticket is now "torn" and can never be used again`}
                language="javascript"
                maxHeight="200px"
              />
              <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                🔐 Also uses ECDH with P-256 - same math, but each key is cryptographically unique
              </Typography>
            </Paper>
            
            <Paper sx={{ p: 3, bgcolor: 'warning.light', color: 'warning.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>4. ⚡ Ephemeral Keys (Lightning Bolts)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What they do:</strong> Like lightning - created instantly, used once, disappear forever.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why we need them:</strong> Adds extra randomness so even if someone records everything, 
                they still can't decrypt without this key that no longer exists.
              </Typography>
              <CodeDisplay 
                code={`// JavaScript: How Alice creates ephemeral keys
// This happens fresh every time Alice wants to start a conversation
const ephemeralKeyPair = await crypto.generateSignalKeyPair();

console.log("Alice created lightning bolt key");

// Alice uses this key for the X3DH calculation
const sharedSecret = performMagicalCombination(
  ephemeralKeyPair.privateKey,  // Alice's lightning (disappears after use)
  bob.signedPrekey,            // Bob's office badge
  bob.oneTimePrekey,           // Bob's concert ticket
  bob.identityKey              // Bob's house address
);

// IMPORTANT: Alice immediately throws away the private key!
delete ephemeralKeyPair.privateKey;

console.log("Lightning key destroyed - conversation now has perfect forward secrecy!");`}
                language="javascript"
                maxHeight="250px"
              />
              <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                🔐 ECDH with P-256 again - the same trusted math, but this key exists for seconds only
              </Typography>
            </Paper>
          </Box>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>{'🧠'} Why These Four Key Types Together Are Genius:</Typography>
            <Typography variant="body2" paragraph>
              Each key type solves a different problem. If we only used one type of key:
            </Typography>
            <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
              <li><strong>Only identity keys:</strong> Old messages become readable if key is stolen</li>
              <li><strong>Only ephemeral keys:</strong> Can't prove who sent the message (no authentication)</li>
              <li><strong>Only long-term keys:</strong> No forward secrecy if compromised</li>
              <li><strong>Only one-time keys:</strong> Would run out quickly and be hard to manage</li>
            </Box>
            <Typography variant="body2" sx={{ mt: 2 }}>
              <strong>Together:</strong> They create a system where you get authentication, forward secrecy, 
              asynchronous messaging, AND protection against future key compromises!
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🛡️ X3DH: The Complete Recipe (Step-by-Step Code)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              🧑‍🍳 Let's Cook Up Some Cryptographic Magic!
            </Typography>
            <Typography variant="body2">
              Here's the <strong>complete JavaScript recipe</strong> for creating a secure conversation between Alice and Bob. 
              We'll explain every ingredient and why it's needed!
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'primary.main' }}>
            <Typography variant="h5" gutterBottom color="primary">
              🥘 Step 1: Gather All The Ingredients (Key Generation)
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="primary">
                      👩 Alice's Preparation:
                    </Typography>
                    <CodeDisplay 
                      code={`// Alice creates her identity (like getting an ID card)
const alice = await crypto.initializeSignalUser("Alice");

// Alice creates a lightning bolt key for this conversation
const aliceEphemeral = await crypto.generateSignalKeyPair();

console.log("Alice is ready to send secure messages!");

// What Alice has now:
// 1. Identity key pair (her ID card + private signature)
// 2. Ephemeral key pair (lightning bolt that will be destroyed)`}
                      language="javascript"
                      maxHeight="200px"
                    />
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="secondary">
                      👨 Bob's Preparation:
                    </Typography>
                    <CodeDisplay 
                      code={`// Bob creates his identity
const bob = await crypto.initializeSignalUser("Bob");

// Bob creates his "public bulletin board" (key bundle)
const bobBundle = await crypto.getSignalPublicKeyBundle(bob);

console.log("Bob has posted his public keys for Alice to find!");

// What Bob has prepared:
// 1. Identity key pair (his ID card)
// 2. Signed prekey (office badge, renewed weekly)
// 3. One-time prekeys (concert tickets, use once)
// 4. All public keys posted on server for Alice`}
                      language="javascript"
                      maxHeight="200px"
                    />
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'warning.main' }}>
            <Typography variant="h5" gutterBottom color="warning.main">
              🧮 Step 2: The Magical Math (X3DH Key Exchange)
            </Typography>
            
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>ELI5 Math Explanation:</strong> When Alice and Bob each have puzzle pieces that fit together, 
                they can combine them to create the exact same secret number - even though they never shared that number directly!
              </Typography>
            </Alert>

            <CodeDisplay 
              code={`// Alice performs the X3DH magic spell
const exchangeResult = await crypto.performSignalX3DHKeyExchange(alice, bobBundle);

console.log("🎉 Alice created a shared secret!");

// What just happened behind the scenes (the "magical math"):
// 
// DH1 = ECDH(Alice.Identity.Private, Bob.SignedPrekey.Public)
// DH2 = ECDH(Alice.Ephemeral.Private, Bob.Identity.Public) 
// DH3 = ECDH(Alice.Ephemeral.Private, Bob.SignedPrekey.Public)
// DH4 = ECDH(Alice.Ephemeral.Private, Bob.OneTimePrekey.Public) // if available
//
// MasterSecret = HKDF(DH1 || DH2 || DH3 || DH4, "SignalProtocolContext")
//
// Translation:
// - Alice's private keys + Bob's public keys = Same secret number
// - Bob's private keys + Alice's public keys = Same secret number  
// - Math guarantees they're identical!

const aliceSecret = exchangeResult.masterSecret;`}
              language="javascript"
              maxHeight="300px"
            />
            
            <Alert severity="warning" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>{'🧠'} Why This Math Works:</strong> Elliptic Curve Diffie-Hellman (ECDH) has a special property - 
                when you multiply Alice's private key with Bob's public key, you get the same result as 
                multiplying Bob's private key with Alice's public key. It's like both people having different 
                halves of the same combination lock!
              </Typography>
            </Alert>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'success.main' }}>
            <Typography variant="h5" gutterBottom color="success.main">
              🔄 Step 3: Bob Creates the Same Secret (Verification)
            </Typography>
            
            <CodeDisplay 
              code={`// Bob derives the same secret using Alice's public ephemeral key
const aliceEphemeralPublic = exchangeResult.aliceEphemeralPublic;
const aliceIdentityPublic = await crypto.exportSignalPublicKey(alice.identityKeyPair.publicKey);

// Bob performs the same mathematical operations but with his private keys
const bobSecret = await crypto.deriveSignalSharedSecret(
  bob,                        // Bob's identity and prekeys
  aliceEphemeralPublic,       // Alice's lightning bolt (public part)
  aliceIdentityPublic,        // Alice's ID card (public part) 
  exchangeResult.usedOneTimePrekey, // Which ticket was used
  bobBundle.oneTimePrekey     // Bob's actual ticket (private part)
);

// Convert secrets to human-readable hex for comparison
const aliceSecretHex = crypto.bufferToSignalHex(aliceSecret);
const bobSecretHex = crypto.bufferToSignalHex(bobSecret);

const success = aliceSecretHex === bobSecretHex;
console.log("Secrets match:", success);

if (success) {
  console.log("🎉 SUCCESS! Alice and Bob now share the same secret!");
  console.log("🔒 They can now encrypt messages that only they can read!");
} else {
  console.log("❌ FAILED! Something went wrong in the key exchange!");
}`}
              language="javascript"
              maxHeight="350px"
            />
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'error.main' }}>
            <Typography variant="h5" gutterBottom color="error.main">
              🧹 Step 4: Clean Up for Security (Forward Secrecy)
            </Typography>
            
            <CodeDisplay 
              code={`// CRITICAL: Destroy evidence for forward secrecy
// Alice deletes her ephemeral private key (lightning bolt disappears)
delete aliceEphemeral.privateKey;

// Bob consumes his one-time prekey (tears up the concert ticket)
if (exchangeResult.usedOneTimePrekey) {
  crypto.consumeSignalOneTimePrekey(bob);
  console.log("🎫 Bob's concert ticket has been torn up - can never be used again!");
}

// Now even if someone steals all the long-term keys:
// - They can't decrypt this conversation (ephemeral key is gone)
// - They can't replay this exchange (one-time key is consumed)
// - Future conversations will use new ephemeral keys

console.log("🛡️ Forward secrecy achieved!");
console.log("🗑️ All temporary keys have been securely destroyed!");

// What remains:
// - Identity keys (still needed for future conversations)
// - Signed prekeys (still needed for asynchronous messaging)  
// - The shared secret (used to encrypt actual messages)
// - Perfect forward secrecy (this conversation is quantum-resistant)`}
              language="javascript"
              maxHeight="300px"
            />
          </Paper>

          <Alert severity="success" sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              🎯 Mission Accomplished: What We Just Built
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>🔐 Authentication</Typography>
                    <Typography variant="body2">
                      Bob knows the message really came from Alice (identity keys prove it)
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>⚡ Forward Secrecy</Typography>
                    <Typography variant="body2">
                      Old messages stay secret even if keys are stolen later (ephemeral keys destroyed)
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>🎫 Perfect Secrecy</Typography>
                    <Typography variant="body2">
                      Each conversation is unique (one-time keys provide fresh randomness)
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🔬 Algorithm Choices Explained (Why These Specific Algorithms?)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              🤔 Why These Specific Algorithms?
            </Typography>
            <Typography variant="body2">
              Every algorithm in Signal Protocol was chosen for specific security reasons. 
              Let's explain why we use each one, like explaining why a chef chooses specific ingredients!
            </Typography>
          </Alert>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Paper sx={{ p: 3, bgcolor: 'primary.light', color: 'primary.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>🔢 ECDH with P-256 Curve (Key Agreement)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What it does:</strong> Lets two people create the same secret number without ever sharing it directly.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why P-256 specifically:</strong>
              </Typography>
              <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
                <li>🏛️ <strong>Government approved:</strong> NIST standard, trusted by banks and governments</li>
                <li>⚡ <strong>Fast:</strong> Hardware acceleration in most modern devices</li>
                <li>🔐 <strong>Strong:</strong> 256-bit keys = virtually impossible to break (even with quantum computers for now)</li>
                <li>🌍 <strong>Universal:</strong> Supported by all modern browsers and devices</li>
              </Box>
              <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                Note: Signal actually uses Curve25519 (which is faster), but this demo uses P-256 for browser compatibility
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, bgcolor: 'secondary.light', color: 'secondary.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>✍️ ECDSA with P-256 (Digital Signatures)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What it does:</strong> Creates unforgeable digital signatures to prove who sent a message.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why ECDSA specifically:</strong>
              </Typography>
              <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
                <li>🎯 <strong>Perfect match:</strong> Uses same curve as ECDH, so we only need one math library</li>
                <li>⚖️ <strong>Non-repudiation:</strong> Impossible to forge someone else's signature</li>
                <li>📏 <strong>Compact:</strong> Small signature size (64 bytes) saves bandwidth</li>
                <li>🛡️ <strong>Battle-tested:</strong> Used in Bitcoin, TLS, and most secure systems</li>
              </Box>
            </Paper>

            <Paper sx={{ p: 3, bgcolor: 'success.light', color: 'success.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>{'🧂'} HKDF-SHA256 (Key Derivation)</Typography>
              <Typography variant="body2" paragraph>
                <strong>What it does:</strong> Takes multiple secret ingredients and mixes them into one perfect secret sauce.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Why HKDF with SHA256:</strong>
              </Typography>
              <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
                <li>🌪️ <strong>Entropy extraction:</strong> Squeezes maximum randomness from imperfect sources</li>
                <li>🎯 <strong>Domain separation:</strong> Different contexts produce completely different keys</li>
                <li>🔒 <strong>One-way function:</strong> Impossible to reverse-engineer the original secrets</li>
                <li>📏 <strong>Length extension:</strong> Can produce keys of any needed length</li>
                <li>🏆 <strong>Proven secure:</strong> RFC 5869 standard with formal security proofs</li>
              </Box>
              <CodeDisplay 
                code={`// How HKDF works in simple terms:
// Input: DH1 + DH2 + DH3 + DH4 (raw shared secrets)
// Salt: "Signal_X3DH" (prevents rainbow table attacks)  
// Output: 32 bytes of perfect randomness

const masterSecret = HKDF_SHA256(
  DH1 || DH2 || DH3 || DH4,        // All the puzzle pieces combined
  "Signal_X3DH_Key_Derivation",    // Context label (like a recipe name)
  32                               // How many bytes of secret we want
);

// Result: Cryptographically perfect shared secret!`}
                language="javascript"
                maxHeight="180px"
              />
            </Paper>

            <Paper sx={{ p: 3, bgcolor: 'warning.light', color: 'warning.contrastText', borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>{'🧠'} Why Not Just Use One Algorithm?</Typography>
              <Typography variant="body2" paragraph>
                <strong>The Security Principle:</strong> "Defense in Depth"
              </Typography>
              <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
                <li><strong>If ECDH breaks:</strong> ECDSA signatures still prove authenticity</li>
                <li><strong>If SHA256 breaks:</strong> ECDH still provides core secrecy</li>
                <li><strong>If P-256 breaks:</strong> System can be upgraded to new curves</li>
                <li><strong>If one key type compromised:</strong> Other key types maintain security</li>
              </Box>
              <Typography variant="body2" sx={{ mt: 2 }}>
                <strong>Real-world analogy:</strong> It's like a bank vault with multiple locks, alarms, 
                guards, and cameras. If one security measure fails, the others still protect the treasure!
              </Typography>
            </Paper>
          </Box>

          <Alert severity="success" sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              🎯 The Bottom Line: Why Signal Protocol Is Considered "Gold Standard"
            </Typography>
            <Typography variant="body2">
              Signal Protocol combines <strong>multiple proven algorithms</strong> in a way that creates security properties 
              that no single algorithm can provide alone. It's not just about the math - it's about how the math 
              works together to protect billions of conversations every day! 🌟
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🛡️ Security Guarantees (What Protection Do You Actually Get?)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Alert severity="info">
              <Typography variant="subtitle2">🕰️ Forward Secrecy (Your Past Is Safe)</Typography>
              <Typography variant="body2">
                <strong>ELI5:</strong> Even if someone steals your phone tomorrow, they can't read messages you sent last week.
                <br />
                <strong>Why:</strong> Old messages were encrypted with "lightning bolt keys" that were destroyed immediately after use.
              </Typography>
            </Alert>
            
            <Alert severity="info">
              <Typography variant="subtitle2">🔮 Future Secrecy (Your Future Is Safe)</Typography>
              <Typography variant="body2">
                <strong>ELI5:</strong> If someone hacks your current conversation, they still can't read your future conversations.
                <br />
                <strong>Why:</strong> Each new conversation creates completely new "lightning bolt keys" with fresh randomness.
              </Typography>
            </Alert>
            
            <Alert severity="success">
              <Typography variant="subtitle2">🆔 Mutual Authentication (You Know Who You're Talking To)</Typography>
              <Typography variant="body2">
                <strong>ELI5:</strong> You can be 100% sure messages actually came from your friend, not an imposter.
                <br />
                <strong>Why:</strong> Identity keys work like unforgeable digital signatures that only the real person can create.
              </Typography>
            </Alert>
            
            <Alert severity="success">
              <Typography variant="subtitle2">🎫 Perfect Forward Secrecy (Every Chat Is Unique)</Typography>
              <Typography variant="body2">
                <strong>ELI5:</strong> Each conversation is like a unique snowflake - even identical messages have different encryption.
                <br />
                <strong>Why:</strong> One-time prekeys add fresh randomness that can never be recreated or reused.
              </Typography>
            </Alert>
            
            <Alert severity="warning">
              <Typography variant="subtitle2">🤐 Deniability (Plausible Deniability)</Typography>
              <Typography variant="body2">
                <strong>ELI5:</strong> You can't prove to a judge that someone sent a specific message (this protects whistleblowers).
                <br />
                <strong>Why:</strong> Anyone with the shared secret could have created the same encrypted message.
              </Typography>
            </Alert>
          </Box>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">💾 Your Personal Key Filing Cabinet (ELI5 Key Storage)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              📁 Think of Key Storage Like Your Filing Cabinet at Home
            </Typography>
            <Typography variant="body2">
              Just like you have different folders for different types of papers (birth certificate, passport, bills), 
              your phone has different "folders" for different types of keys. Let's see what goes in each folder! 📂
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'primary.light', color: 'primary.contrastText', borderRadius: 2 }}>
            <Typography variant="h5" gutterBottom>
              🗂️ Alice's Key Filing System (What Keys Do I Need to Remember?)
            </Typography>
            
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="primary">
                      📋 My Personal Key List
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>ELI5:</strong> These are like the important papers you keep in your safe at home - they don't change often!
                    </Typography>
                    <Box component="ol" sx={{ pl: 2, '& li': { mb: 1 } }}>
                      <li><strong>🏠 My Identity Key:</strong> Like my birth certificate - proves who I am (NEVER changes)</li>
                      <li><strong>📝 My Signed Office Badge:</strong> Like a work ID - renewed every week for security</li>
                      <li><strong>🎫 My Concert Tickets:</strong> Stack of 100 one-time-use tickets (use one, throw it away)</li>
                      <li><strong>📱 My Phone's Secret Number:</strong> Device-specific key to encrypt my storage</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="secondary">
                      💬 My Conversation Keys
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>ELI5:</strong> These are like the secret codes I share with each friend - one set per friend!
                    </Typography>
                    <Box component="ol" sx={{ pl: 2, '& li': { mb: 1 } }}>
                      <li><strong>🤝 Shared Secret with Bob:</strong> Our special number that only we know</li>
                      <li><strong>📨 Message Counter:</strong> Keeps track of message #1, #2, #3, etc.</li>
                      <li><strong>🔄 Chain Key:</strong> Changes after every message (like a spinning combination lock)</li>
                      <li><strong>⏰ Last Used Date:</strong> When did we last chat?</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            <Alert severity="warning">
              <Typography variant="body2">
                <strong>🔒 Security Note:</strong> In real apps like Signal, these keys are stored in your phone's secure vault 
                (like iOS Keychain or Android KeyStore) - NOT in simple localStorage like this demo!
              </Typography>
            </Alert>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'info.main' }}>
            <Typography variant="h5" gutterBottom color="info.main">
              🗃️ How Alice Organizes Her Key Filing Cabinet (Step by Step)
            </Typography>
            
            <Alert severity="success" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>ELI5 Analogy:</strong> Think of this like Alice organizing her important papers in a filing cabinet. 
                Each drawer has a specific purpose and she knows exactly what goes where! 📁
              </Typography>
            </Alert>

            <CodeDisplay 
              code={`// Alice's Personal Filing System (ELI5 Version)
class MyKeyFilingCabinet {
  constructor(myName) {
    this.myName = myName;
    this.cabinetLabel = \`\${myName}'s_Secret_Keys\`;
    console.log(\`📁 Setting up filing cabinet for \${myName}\`);
  }

  // STEP 1: Put all my important papers in the filing cabinet
  async saveMyImportantPapers(myKeys) {
    console.log(\`🗂️ \${this.myName} is filing away important papers...\`);
    
    // My filing system with clear labels:
    const myFilingSystem = {
      // DRAWER 1: My permanent identity documents
      myIdentityPapers: {
        myPublicBirthCertificate: "This proves who I am to the world",
        myPrivateSocialSecurity: "This is secret - only I know this number!",
        label: "🏠 IDENTITY DRAWER - Never changes"
      },
      
      // DRAWER 2: My weekly work ID badge  
      myWorkBadge: {
        publicWorkBadge: "Everyone can see this badge",
        privateAccessCode: "Secret code to get into work building", 
        renewalDate: Date.now(),
        label: "📝 WORK DRAWER - Renewed every Monday"
      },
      
      // DRAWER 3: My stack of movie tickets (use once, throw away)
      myTicketStack: {
        ticketsRemaining: 100,  // I start with 100 tickets
        nextTicketNumber: 1,    // Next ticket to use is #1
        label: "🎫 TICKET DRAWER - Use one, throw it away"
      },
      
      // FILING CABINET METADATA
      owner: this.myName,
      whenCreated: Date.now(),
      lastOrganized: Date.now(),
      securityLevel: "TOP SECRET 🔒"
    };

    // Save to my secure filing cabinet (in real life: encrypted vault!)
    localStorage.setItem(this.cabinetLabel, JSON.stringify(myFilingSystem));
    
    console.log(\`✅ \${this.myName}'s filing cabinet is all organized!\`);
    console.log("📋 Filed papers:");
    console.log("   🏠 Identity documents (permanent)");
    console.log("   📝 Work badge (weekly renewal)"); 
    console.log("   🎫 100 movie tickets (single use)");
  }

  // STEP 2: Open my filing cabinet and get my papers when I need them
  async getMyPapersFromFilingCabinet() {
    const myFiledPapers = localStorage.getItem(this.cabinetLabel);
    
    if (!myFiledPapers) {
      console.log(\`😰 \${this.myName}'s filing cabinet is empty! Need to set it up first.\`);
      return null;
    }

    const myPapers = JSON.parse(myFiledPapers);
    console.log(\`📂 \${this.myName} opened the filing cabinet\`);
    console.log(\`📋 Found papers last organized: \${new Date(myPapers.lastOrganized).toLocaleDateString()}\`);
    
    // Check what papers I have available
    console.log("📁 Available papers:");
    console.log(\`   🏠 Identity: \${myPapers.myIdentityPapers.label}\`);
    console.log(\`   📝 Work badge: \${myPapers.myWorkBadge.label}\`); 
    console.log(\`   🎫 Tickets left: \${myPapers.myTicketStack.ticketsRemaining}\`);
    
    return myPapers;
  }

  // STEP 3: Check if I need to renew my work badge (every Monday)
  needToRenewWorkBadge() {
    const myPapers = localStorage.getItem(this.cabinetLabel);
    if (!myPapers) return true;
    
    const papers = JSON.parse(myPapers);
    const oneWeekInMs = 7 * 24 * 60 * 60 * 1000;  // 7 days
    const timeSinceLastRenewal = Date.now() - papers.myWorkBadge.renewalDate;
    
    if (timeSinceLastRenewal > oneWeekInMs) {
      console.log(\`⏰ \${this.myName}'s work badge expired! Time to renew.\`);
      return true;
    }
    
    console.log(\`✅ \${this.myName}'s work badge is still valid\`);
    return false;
  }

  // STEP 4: Use one of my movie tickets (and throw it away)
  useOneMovieTicket() {
    const myPapers = JSON.parse(localStorage.getItem(this.cabinetLabel));
    
    if (myPapers.myTicketStack.ticketsRemaining > 0) {
      myPapers.myTicketStack.ticketsRemaining--;
      myPapers.myTicketStack.nextTicketNumber++;
      
      localStorage.setItem(this.cabinetLabel, JSON.stringify(myPapers));
      
      console.log(\`🎫 \${this.myName} used ticket #\${myPapers.myTicketStack.nextTicketNumber - 1}\`);
      console.log(\`📊 Tickets remaining: \${myPapers.myTicketStack.ticketsRemaining}\`);
      
      return \`ticket_\${myPapers.myTicketStack.nextTicketNumber - 1}\`;
    } else {
      console.log(\`😱 \${this.myName} ran out of movie tickets! Need to get more.\`);
      return null;
    }
  }
}

// EXAMPLE: Alice sets up her personal filing cabinet
console.log("🚀 Alice is setting up her key filing cabinet...");

const aliceFilingCabinet = new MyKeyFilingCabinet("Alice");
const aliceKeys = await crypto.initializeSignalUser("Alice");

// Alice organizes all her important papers
await aliceFilingCabinet.saveMyImportantPapers(aliceKeys);

// Later, Alice opens her filing cabinet to get her papers
const alicePapers = await aliceFilingCabinet.getMyPapersFromFilingCabinet();

// Alice checks if she needs to renew her work badge
if (aliceFilingCabinet.needToRenewWorkBadge()) {
  console.log("🔄 Time to get a new work badge!");
}

// Alice uses one of her movie tickets
const usedTicket = aliceFilingCabinet.useOneMovieTicket();
console.log(\`🎬 Alice went to the movies with \${usedTicket}!\`);`}
              language="javascript"
              maxHeight="800px"
            />
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'success.main' }}>
            <Typography variant="h5" gutterBottom color="success.main">
              🔄 Shared Secret Persistence & Conversation State
            </Typography>
            
            <CodeDisplay 
              code={`// Store conversation secrets for ongoing messaging
class ConversationStore {
  constructor(localUserId, remoteUserId) {
    this.conversationId = \`\${localUserId}_\${remoteUserId}\`;
    this.storageKey = \`conversation_\${this.conversationId}\`;
  }

  // Save shared secret after X3DH key exchange
  async saveSharedSecret(sharedSecret, ephemeralPublic, usedOneTimePrekey) {
    const conversationState = {
      // The master secret from X3DH
      sharedSecret: crypto.bufferToSignalHex(sharedSecret),
      
      // Key exchange metadata  
      ephemeralPublic: crypto.bufferToSignalHex(ephemeralPublic),
      usedOneTimePrekey: usedOneTimePrekey,
      
      // Message chain state (for Double Ratchet)
      sendingChainKey: crypto.bufferToSignalHex(sharedSecret), // Initial chain key
      receivingChainKey: null, // Will be derived when first message received
      messageNumber: 0,
      
      // Security metadata
      established: Date.now(),
      lastMessageTime: Date.now()
    };

    localStorage.setItem(this.storageKey, JSON.stringify(conversationState));
    console.log(\`💬 Conversation state saved for \${this.conversationId}\`);
  }

  // Load conversation state
  loadConversationState() {
    const stored = localStorage.getItem(this.storageKey);
    if (!stored) return null;
    
    const state = JSON.parse(stored);
    console.log(\`💬 Loaded conversation state for \${this.conversationId}\`);
    return {
      ...state,
      sharedSecret: new Uint8Array(state.sharedSecret.match(/.{2}/g).map(byte => parseInt(byte, 16))).buffer
    };
  }

  // Update message chain state after each message
  updateMessageState(newChainKey, messageNumber) {
    const state = this.loadConversationState();
    if (state) {
      state.sendingChainKey = crypto.bufferToSignalHex(newChainKey);
      state.messageNumber = messageNumber;
      state.lastMessageTime = Date.now();
      localStorage.setItem(this.storageKey, JSON.stringify(state));
    }
  }
}

// Example: Save conversation state after X3DH
const conversation = new ConversationStore("Alice", "Bob");
await conversation.saveSharedSecret(
  exchangeResult.masterSecret,
  exchangeResult.aliceEphemeralPublic, 
  exchangeResult.usedOneTimePrekey
);`}
              language="javascript"
              maxHeight="500px"
            />
          </Paper>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              {'🔐'} Production Security Considerations
            </Typography>
            <Box component="ul" sx={{ pl: 2, '& li': { mb: 1 } }}>
              <li><strong>Encryption at Rest:</strong> All stored keys encrypted with device-specific keys</li>
              <li><strong>Key Derivation:</strong> Use PBKDF2 or Argon2 to derive storage encryption keys from user passwords</li>
              <li><strong>Secure Enclaves:</strong> iOS Keychain, Android KeyStore for hardware-backed security</li>
              <li><strong>Key Rotation:</strong> Automatic weekly rotation of signed prekeys</li>
              <li><strong>Forward Secrecy:</strong> Ephemeral keys never stored, only used once</li>
            </Box>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">💌 Sending Secret Messages Like a Spy (ELI5 Message Encryption)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              🕵️ Alice and Bob's Secret Message System
            </Typography>
            <Typography variant="body2">
              Now Alice and Bob have their shared secret from the key exchange - it's like they both know the same magic spell! 
              Let's see how they use it to send messages that only they can understand! ✨
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'warning.light', color: 'warning.contrastText', borderRadius: 2 }}>
            <Typography variant="h5" gutterBottom>
              🧙‍♀️ Alice's Message Magic Spell Book (What Keys Change When?)
            </Typography>
            
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="error">
                      🔄 Keys That Change Every Message
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>ELI5:</strong> These are like using a new password for each text message!
                    </Typography>
                    <Box component="ol" sx={{ pl: 2, '& li': { mb: 1 } }}>
                      <li><strong>🔑 Message Key:</strong> Brand new key for each message (like a new padlock)</li>
                      <li><strong>📊 Message Number:</strong> Counts up: 1, 2, 3, 4... (like page numbers)</li>
                      <li><strong>🎲 Random Numbers:</strong> Fresh random salt for each message</li>
                      <li><strong>🔄 Chain Key:</strong> Updates after each message (like spinning a combination lock)</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="success">
                      🏠 Keys That Stay the Same
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>ELI5:</strong> These are like your house address - they don't change during the conversation!
                    </Typography>
                    <Box component="ol" sx={{ pl: 2, '& li': { mb: 1 } }}>
                      <li><strong>🤝 Shared Secret:</strong> The magic number Alice & Bob both know</li>
                      <li><strong>🏠 Identity Keys:</strong> Proof of who Alice and Bob really are</li>
                      <li><strong>👤 Conversation ID:</strong> "Alice talking to Bob" label</li>
                      <li><strong>⚡ Ephemeral Key:</strong> Already used and thrown away after X3DH</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            <Alert severity="info">
              <Typography variant="body2">
                <strong>{'🧠'} The Smart Part:</strong> By changing some keys every message but keeping others the same, 
                Alice and Bob get <strong>both</strong> security (new keys = new protection) <strong>and</strong> convenience 
                (same shared secret = no need to do key exchange again)!
              </Typography>
            </Alert>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'primary.main' }}>
            <Typography variant="h5" gutterBottom color="primary">
              🎬 Alice's Secret Message Machine (Step-by-Step Like Making a Sandwich)
            </Typography>
            
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>ELI5 Analogy:</strong> Alice has a special sandwich-making machine! Each sandwich (message) gets 
                wrapped in a different colored wrapper (encryption key), but the recipe stays the same! 🥪
              </Typography>
            </Alert>

            <CodeDisplay 
              code={`// Alice's Secret Message Machine (ELI5 Version)
class MySecretMessageMachine {
  constructor(mySharedSecretWithFriend) {
    this.mySharedSecret = mySharedSecretWithFriend;  // The magic spell we both know
    this.messageCounter = 0;  // Keeps track: message 1, 2, 3...
    console.log("🤖 Alice's secret message machine is ready!");
  }

  // STEP 1: Make a brand new key for this specific message
  async makeNewMessageKey(messageNumber) {
    console.log(\`🔧 Making a brand new key for message #\${messageNumber}\`);
    
    // ELI5: Mix the shared secret + message number = unique key
    const recipe = \`My shared secret + message number \${messageNumber}\`;
    const ingredientsToMix = new TextEncoder().encode(recipe);
    
    // Mix all ingredients together (like making cake batter)
    const combinedIngredients = new Uint8Array(
      this.mySharedSecret.byteLength + ingredientsToMix.byteLength
    );
    combinedIngredients.set(new Uint8Array(this.mySharedSecret));
    combinedIngredients.set(ingredientsToMix, this.mySharedSecret.byteLength);
    
    // Put it in the special mixing machine (hash function)
    const mixedResult = await crypto.sha256Hash(combinedIngredients.buffer);
    
    console.log(\`✅ Made fresh key for message #\${messageNumber}!\`);
    return mixedResult;
  }

  // STEP 2: Encrypt Alice's secret message like wrapping a present
  async wrapMySecretMessage(myMessage) {
    this.messageCounter++;  // Count: 1, 2, 3, 4...
    
    console.log(\`📝 Alice wants to send: "\${myMessage}"\`);
    console.log(\`📊 This is message number: \${this.messageCounter}\`);

    // Make a fresh key just for this message
    const freshKeyIngredients = await this.makeNewMessageKey(this.messageCounter);
    
    // Split the mixed ingredients into different jobs:
    const wrappingKey = freshKeyIngredients.slice(0, 32);   // For wrapping (encryption)
    const securityStamp = freshKeyIngredients.slice(32, 64); // For security seal (MAC) 
    const uniqueLabel = freshKeyIngredients.slice(64, 80);   // For unique ID (IV)
    
    console.log("🎁 Alice is wrapping her message...");
    
    // Convert Alice's message to secret code
    const messageInSecretCode = new TextEncoder().encode(myMessage);
    
    // Wrap the message with the special wrapping key
    const wrappedMessage = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: uniqueLabel },
      await crypto.subtle.importKey("raw", wrappingKey, { name: "AES-GCM" }, false, ["encrypt"]),
      messageInSecretCode
    );

    // Create the package label (everyone can see this part)
    const packageLabel = {
      wrappedMessage: Array.from(new Uint8Array(wrappedMessage)),
      messageNumber: this.messageCounter,
      timeStamp: Date.now(),
      fromAlice: "This package is from Alice",
      toBob: "This package is for Bob only"
    };

    console.log(\`📦 Message #\${this.messageCounter} is wrapped and ready to mail!\`);
    console.log("📮 Package label shows message number and timestamp (not secret)");
    console.log("🔒 But the actual message inside is completely scrambled!");
    
    return packageLabel;
  }

  // STEP 3: Bob unwraps Alice's secret message
  async unwrapSecretMessage(packageFromAlice) {
    console.log(\`📬 Bob received package #\${packageFromAlice.messageNumber} from Alice\`);

    // Bob makes the same key Alice used (same recipe!)
    const sameKeyAliceUsed = await this.makeNewMessageKey(packageFromAlice.messageNumber);
    const sameWrappingKey = sameKeyAliceUsed.slice(0, 32);
    const sameUniqueLabel = sameKeyAliceUsed.slice(64, 80);

    console.log("🔧 Bob is making the same unwrapping key Alice used...");

    // Unwrap the message with the matching key
    const wrappedMessage = new Uint8Array(packageFromAlice.wrappedMessage).buffer;
    
    try {
      const unwrappedMessage = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: sameUniqueLabel },
        await crypto.subtle.importKey("raw", sameWrappingKey, { name: "AES-GCM" }, false, ["decrypt"]),
        wrappedMessage
      );

      const alicesOriginalMessage = new TextDecoder().decode(unwrappedMessage);
      console.log(\`🎉 Bob unwrapped the message: "\${alicesOriginalMessage}"\`);
      console.log("✅ SUCCESS! Bob can read Alice's secret message!");
      return alicesOriginalMessage;
      
    } catch (error) {
      console.error("❌ Bob couldn't unwrap the message!");
      console.error("🚫 Either the package was damaged or someone tried to tamper with it!");
      throw new Error("Message unwrapping failed - package might be damaged");
    }
  }

  // STEP 4: Update the conversation state (like turning pages in a book)
  updateConversationPage() {
    console.log(\`📖 Conversation moved to page \${this.messageCounter + 1}\`);
    console.log("🔄 Next message will use a completely different key!");
    
    // The shared secret stays the same, but message counter goes up
    return {
      messagesExchanged: this.messageCounter,
      nextMessageNumber: this.messageCounter + 1,
      sharedSecretStillValid: true
    };
  }
}

// EXAMPLE: Alice and Bob's secret conversation
console.log("🚀 Starting Alice and Bob's secret message exchange...");

// Both Alice and Bob have the same shared secret (from X3DH key exchange)
const sharedSecret = new TextEncoder().encode("AliceAndBobsSharedSecret123").buffer;

const alicesMessageMachine = new MySecretMessageMachine(sharedSecret);
const bobsMessageMachine = new MySecretMessageMachine(sharedSecret);

// Alice sends her first secret message
const alicesMessage = "Hey Bob! 🤫 This is our secret chat!";
const wrappedPackage = await alicesMessageMachine.wrapMySecretMessage(alicesMessage);

console.log("\\n📨 Package ready to send:", {
  messageNumber: wrappedPackage.messageNumber,
  timestamp: new Date(wrappedPackage.timeStamp).toLocaleTimeString(),
  packageSize: wrappedPackage.wrappedMessage.length + " bytes",
  actualMessage: "🔒 ENCRYPTED - Can't see without the key!"
});

// Bob receives and unwraps the package
console.log("\\n📬 Bob is opening the package...");
const bobsDecryptedMessage = await bobsMessageMachine.unwrapSecretMessage(wrappedPackage);

// Update conversation state
const conversationStatus = alicesMessageMachine.updateConversationPage();
console.log("\\n📊 Conversation Status:", conversationStatus);`}
              language="javascript"
              maxHeight="1000px"
            />
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'error.light', color: 'error.contrastText', borderRadius: 2 }}>
            <Typography variant="h5" gutterBottom>
              📅 When Do Keys Get Updated? (ELI5 Key Lifecycle)
            </Typography>
            
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="success">
                      ✅ Every Single Message
                    </Typography>
                    <Box component="ul" sx={{ pl: 2, fontSize: '0.9rem', '& li': { mb: 1 } }}>
                      <li><strong>Message Number:</strong> 1 → 2 → 3 → 4...</li>
                      <li><strong>Message Key:</strong> Completely new key</li>
                      <li><strong>Random IV:</strong> Fresh randomness</li>
                      <li><strong>Timestamp:</strong> When message was sent</li>
                    </Box>
                    <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                      🔄 These change automatically with every text!
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="warning">
                      ⏰ Every Week
                    </Typography>
                    <Box component="ul" sx={{ pl: 2, fontSize: '0.9rem', '& li': { mb: 1 } }}>
                      <li><strong>Signed Prekeys:</strong> New work badge</li>
                      <li><strong>One-time Prekeys:</strong> Refill ticket stack</li>
                      <li><strong>Key Rotation:</strong> Auto-scheduled</li>
                      <li><strong>Old Keys:</strong> Thrown away safely</li>
                    </Box>
                    <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                      📅 Your phone does this automatically every Monday!
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom color="info">
                      🏠 Almost Never
                    </Typography>
                    <Box component="ul" sx={{ pl: 2, fontSize: '0.9rem', '& li': { mb: 1 } }}>
                      <li><strong>Identity Keys:</strong> Like birth certificate</li>
                      <li><strong>Shared Secrets:</strong> Per-conversation magic number</li>
                      <li><strong>User ID:</strong> Your unique identifier</li>
                      <li><strong>Device Keys:</strong> Phone-specific keys</li>
                    </Box>
                    <Typography variant="caption" display="block" sx={{ mt: 1, fontStyle: 'italic' }}>
                      🔒 These stay the same for months or years!
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            <Alert severity="warning">
              <Typography variant="body2">
                <strong>{'🧠'} Smart Design:</strong> By updating different keys at different times, Signal Protocol gets 
                maximum security (fresh keys often) with minimum hassle (don't need to redo key exchange constantly)!
              </Typography>
            </Alert>
          </Paper>

          <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50', border: '2px solid', borderColor: 'warning.main' }}>
            <Typography variant="h5" gutterBottom color="warning.main">
              💬 Full Conversation: Alice Sends 5 Messages (Watch Keys Update!)
            </Typography>
            
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>ELI5:</strong> Let's watch Alice send multiple messages to Bob and see exactly which keys change and which stay the same! 
                It's like watching a conveyor belt where some parts move and others stay still! 🏭
              </Typography>
            </Alert>
            
            <CodeDisplay 
              code={`// Complete example: From key exchange to encrypted chat
async function completeSignalDemo() {
  console.log("🚀 Starting complete Signal Protocol demonstration...");
  
  // === PHASE 1: SETUP AND KEY EXCHANGE ===
  console.log("\\n📋 Phase 1: User Setup & Key Exchange");
  
  // Initialize users
  const alice = await crypto.initializeSignalUser("Alice");
  const bob = await crypto.initializeSignalUser("Bob");
  
  // Set up key storage
  const aliceStore = new SignalKeyStore("Alice");
  const bobStore = new SignalKeyStore("Bob");
  
  // Save keys to storage
  await aliceStore.saveUserKeys(alice);
  await bobStore.saveUserKeys(bob);
  
  // Perform X3DH key exchange
  const bobBundle = await crypto.getSignalPublicKeyBundle(bob);
  const exchangeResult = await crypto.performSignalX3DHKeyExchange(alice, bobBundle);
  
  // Save conversation state
  const conversation = new ConversationStore("Alice", "Bob");
  await conversation.saveSharedSecret(
    exchangeResult.masterSecret,
    exchangeResult.aliceEphemeralPublic,
    exchangeResult.usedOneTimePrekey
  );
  
  console.log("✅ Key exchange complete - shared secret established!");
  
  // === PHASE 2: ENCRYPTED MESSAGING ===
  console.log("\\n💬 Phase 2: Encrypted Messaging");
  
  const conversationState = conversation.loadConversationState();
  const messaging = new SignalMessaging(conversationState);
  
  // Alice sends messages to Bob
  const messages = [
    "Hi Bob! 👋",
    "This is a secret message! 🤫", 
    "Nobody can read this except us! 🔒",
    "Isn't cryptography amazing? ✨"
  ];
  
  const encryptedMessages = [];
  
  for (let i = 0; i < messages.length; i++) {
    const envelope = await messaging.encryptMessage(messages[i]);
    encryptedMessages.push(envelope);
    console.log(\`📤 Message \${i + 1} encrypted and ready to send\`);
  }
  
  // === PHASE 3: BOB RECEIVES AND DECRYPTS ===
  console.log("\\n📥 Phase 3: Bob Receives Messages");
  
  // Bob loads his conversation state
  const bobConversation = new ConversationStore("Bob", "Alice"); // Note: reversed for Bob's perspective
  await bobConversation.saveSharedSecret(
    exchangeResult.masterSecret,
    exchangeResult.aliceEphemeralPublic,
    exchangeResult.usedOneTimePrekey
  );
  
  const bobConversationState = bobConversation.loadConversationState();
  const bobMessaging = new SignalMessaging(bobConversationState);
  
  console.log("\\n🔓 Decrypting all messages:");
  for (let i = 0; i < encryptedMessages.length; i++) {
    const decrypted = await bobMessaging.decryptMessage(encryptedMessages[i]);
    console.log(\`Message \${i + 1}: "\${decrypted}"\`);
  }
  
  // === PHASE 4: CLEANUP FOR FORWARD SECRECY ===
  console.log("\\n🧹 Phase 4: Security Cleanup");
  
  // Consume one-time prekey
  if (exchangeResult.usedOneTimePrekey) {
    crypto.consumeSignalOneTimePrekey(bob);
    console.log("🎫 One-time prekey consumed - perfect forward secrecy maintained");
  }
  
  console.log("\\n🎉 Complete Signal Protocol demonstration finished!");
  console.log("🔒 All messages encrypted and decrypted successfully!");
  console.log("🛡️ Forward secrecy and authentication achieved!");
  
  return {
    success: true,
    messagesExchanged: messages.length,
    encryptedEnvelopes: encryptedMessages,
    conversationState: conversationState
  };
}

// Run the complete demo
const demoResult = await completeSignalDemo();
console.log("Demo completed:", demoResult.success);`}
              language="javascript"
              maxHeight="800px"
            />
          </Paper>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              {'🔍'} What Makes This Secure?
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>🔐 Message-Level Security</Typography>
                    <Box component="ul" sx={{ pl: 2, fontSize: '0.9rem' }}>
                      <li>Each message uses a unique derived key</li>
                      <li>AES-GCM provides encryption + authentication</li>
                      <li>Message numbers prevent replay attacks</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>⚡ Forward Secrecy</Typography>
                    <Box component="ul" sx={{ pl: 2, fontSize: '0.9rem' }}>
                      <li>Message keys derived, never stored</li>
                      <li>One-time prekeys consumed after use</li>
                      <li>Past messages stay secure even if keys stolen</li>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🌍 Real-World Usage</Typography>
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