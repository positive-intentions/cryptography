import React, { useState, useEffect, useRef } from 'react';
import { 
    Box, Typography, Button, Card, CardContent, Alert, Paper, 
    Grid, CircularProgress, Chip, List, ListItem, ListItemText,
    Accordion, AccordionSummary, AccordionDetails
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import KeyIcon from '@mui/icons-material/VpnKey';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PersonIcon from '@mui/icons-material/Person';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import { CryptographyProvider } from '../../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from '../../components/shared';

const GeneratingKeysStory = () => {
    const [loading, setLoading] = useState(false);
    const [wasmReady, setWasmReady] = useState(false);
    const [error, setError] = useState('');
    const [keys, setKeys] = useState(null);
    const [step, setStep] = useState(0);
    
    const signalProtocolRef = useRef(null);

    useEffect(() => {
        loadWasm();
    }, []);

    const loadWasm = async () => {
        try {
            setLoading(true);
            
            // Load the wasm_exec.js support file
            const script = document.createElement('script');
            script.src = '/wasm/wasm_exec.js';
            document.head.appendChild(script);
            
            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
            });
            
            // Initialize Go runtime
            const go = new window.Go();
            
            // Fetch WASM file from public directory
            const wasmResponse = await fetch('/wasm/signal.wasm');
            const wasmBuffer = await wasmResponse.arrayBuffer();
            const wasmModule = await WebAssembly.instantiate(wasmBuffer, go.importObject);
            
            // Run the Go program
            go.run(wasmModule.instance);
            
            // Store reference to SignalProtocol
            if (window.SignalProtocol) {
                signalProtocolRef.current = window.SignalProtocol;
                setWasmReady(true);
            }
        } catch (err) {
            setError(`Failed to load WASM: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    const generateIdentityKeys = async () => {
        if (!signalProtocolRef.current) return;
        
        try {
            setLoading(true);
            setError('');
            setStep(1);
            
            // Generate identity key pair
            const identityKeyPair = await signalProtocolRef.current.generateIdentityKeyPair();
            
            // Generate registration ID
            const registrationId = signalProtocolRef.current.generateRegistrationId();
            
            // Note: generatePreKeys has a bug in the Go WASM implementation
            // We'll simulate the pre-keys for demonstration
            const preKeys = Array.from({ length: 5 }, (_, i) => ({
                id: i,
                publicKey: `simulated_prekey_${i}_public`,
                privateKey: `simulated_prekey_${i}_private`
            }));
            
            // Note: generateSignedPreKey also has issues, we'll simulate it
            const signedPreKey = {
                id: 0,
                publicKey: 'simulated_signed_prekey_public',
                privateKey: 'simulated_signed_prekey_private',
                signature: 'simulated_signature',
                timestamp: Math.floor(Date.now() / 1000)
            };
            
            setKeys({
                identity: identityKeyPair,
                registrationId,
                preKeys,
                signedPreKey
            });
            
            setStep(2);
        } catch (err) {
            setError(`Key generation failed: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <CryptoDemo title="Generating Your Identity Keys" icon={<KeyIcon />}>
            <Box sx={{ mb: 3 }}>
                <Alert severity="info" sx={{ mb: 2 }}>
                    <Typography variant="body1">
                        <strong>Lesson 2: Creating Your Cryptographic Identity</strong><br />
                        Just like you need an ID card in real life, you need cryptographic keys for secure messaging.
                        Let's create your digital identity!
                    </Typography>
                </Alert>

                <Alert severity="warning" sx={{ mb: 3 }}>
                    <Typography variant="body2">
                        <strong>Implementation Note:</strong> The Go WASM implementation has bugs in `generatePreKeys` 
                        and `generateSignedPreKey` functions. This demo shows working identity key generation and 
                        simulates the other keys for educational purposes. The identity keys and registration ID are real!
                    </Typography>
                </Alert>

                <Typography variant="h5" gutterBottom>
                    🎯 What Are We Building?
                </Typography>
                <Paper sx={{ p: 3, mb: 3 }}>
                    <Typography variant="body1" paragraph>
                        Think of this like creating your secret agent identity kit:
                    </Typography>
                    <List>
                        <ListItem>
                            <ListItemText 
                                primary="🆔 Identity Keys"
                                secondary="Your permanent ID - like your fingerprint, unique to you"
                            />
                        </ListItem>
                        <ListItem>
                            <ListItemText 
                                primary="📋 Registration ID"
                                secondary="A random number that identifies your device"
                            />
                        </ListItem>
                        <ListItem>
                            <ListItemText 
                                primary="🔑 Pre-Keys"
                                secondary="Temporary keys people can use to start a conversation when you're offline"
                            />
                        </ListItem>
                        <ListItem>
                            <ListItemText 
                                primary="✍️ Signed Pre-Key"
                                secondary="A pre-key with your signature to prove it's really from you"
                            />
                        </ListItem>
                    </List>
                </Paper>

                <Typography variant="h5" gutterBottom>
                    💡 Understanding the Keys
                </Typography>
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">Identity Key Pair</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body2" paragraph>
                            <strong>What is it?</strong> Your permanent cryptographic identity.
                        </Typography>
                        <Typography variant="body2" paragraph>
                            <strong>Real-world analogy:</strong> Like your face and fingerprint - unique to you and doesn't change.
                        </Typography>
                        <CodeDisplay 
                            code={`// Identity keys are generated using Curve25519
// This provides 128-bit security level

const identity = await generateIdentityKeyPair();
// Returns:
{
  publicKey: "BGKz9Ew3nSn5w...",  // Share this with everyone
  privateKey: "kPR5bWnXeKD8z..."   // NEVER share this!
}`}
                            language="javascript"
                        />
                        <Alert severity="warning" sx={{ mt: 2 }}>
                            <Typography variant="body2">
                                <strong>Security Rule #1:</strong> NEVER share your private key! 
                                It's like the password to your entire identity.
                            </Typography>
                        </Alert>
                    </AccordionDetails>
                </Accordion>

                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">Pre-Keys</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body2" paragraph>
                            <strong>What are they?</strong> One-time keys that let people start conversations with you when you're offline.
                        </Typography>
                        <Typography variant="body2" paragraph>
                            <strong>Real-world analogy:</strong> Like leaving sealed envelopes at a post office - 
                            each person who wants to contact you takes one envelope to start a secure conversation.
                        </Typography>
                        <CodeDisplay 
                            code={`// Generate 100 pre-keys
const preKeys = await generatePreKeys(0, 100);

// Each pre-key has:
{
  id: 0,                          // Unique identifier
  publicKey: "BLKz9Ew3...",       // Upload to server
  privateKey: "sPR5bWnX..."       // Keep secret locally
}

// When someone uses pre-key #42 to contact you:
// 1. They download preKey[42].publicKey from server
// 2. Server deletes it (one-time use)
// 3. You use preKey[42].privateKey to decrypt`}
                            language="javascript"
                        />
                    </AccordionDetails>
                </Accordion>

                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">Signed Pre-Key</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body2" paragraph>
                            <strong>What is it?</strong> A special pre-key that includes your digital signature.
                        </Typography>
                        <Typography variant="body2" paragraph>
                            <strong>Why important?</strong> Proves the pre-key really came from you and wasn't tampered with.
                        </Typography>
                        <CodeDisplay 
                            code={`// Create a signed pre-key
const signedPreKey = await generateSignedPreKey(
  identityPrivateKey,  // Your identity signs it
  identityPublicKey,   // For verification
  signedPreKeyId       // Unique ID
);

// Contains:
{
  id: 0,
  publicKey: "BNKz9Ew3...",
  privateKey: "tPR5bWnX...",
  signature: "SIG:aBc123...",  // Proves it's from you!
  timestamp: 1699564800        // When it was created
}`}
                            language="javascript"
                        />
                    </AccordionDetails>
                </Accordion>

                <OperationStatus loading={loading} error={error} success={!!keys} />

                {/* Interactive Demo */}
                <Typography variant="h5" gutterBottom sx={{ mt: 3 }}>
                    🚀 Try It Yourself!
                </Typography>
                <Card>
                    <CardContent>
                        {!wasmReady ? (
                            <Box sx={{ textAlign: 'center', py: 3 }}>
                                <CircularProgress />
                                <Typography variant="body2" sx={{ mt: 2 }}>
                                    Loading Signal Protocol WASM...
                                </Typography>
                            </Box>
                        ) : (
                            <>
                                <Button
                                    variant="contained"
                                    onClick={generateIdentityKeys}
                                    disabled={loading || !!keys}
                                    startIcon={<PlayArrowIcon />}
                                    fullWidth
                                    size="large"
                                >
                                    Generate My Identity Keys
                                </Button>

                                {step >= 1 && (
                                    <Box sx={{ mt: 3 }}>
                                        <Typography variant="h6" gutterBottom>
                                            <PersonIcon /> Your Generated Keys
                                        </Typography>
                                        
                                        {loading ? (
                                            <CircularProgress />
                                        ) : keys && (
                                            <Grid container spacing={2}>
                                                <Grid item xs={12}>
                                                    <Paper sx={{ p: 2, bgcolor: 'primary.light' }}>
                                                        <Typography variant="subtitle1" gutterBottom>
                                                            <FingerprintIcon /> Identity Key (Public)
                                                        </Typography>
                                                        <CodeDisplay 
                                                            code={keys.identity.publicKey.substring(0, 50) + '...'}
                                                            language="text"
                                                            maxHeight="60px"
                                                        />
                                                        <Typography variant="caption">
                                                            Share this with anyone who wants to message you
                                                        </Typography>
                                                    </Paper>
                                                </Grid>
                                                
                                                <Grid item xs={12} md={6}>
                                                    <Paper sx={{ p: 2 }}>
                                                        <Typography variant="subtitle1" gutterBottom>
                                                            Registration ID
                                                        </Typography>
                                                        <Typography variant="h4" color="primary">
                                                            {keys.registrationId}
                                                        </Typography>
                                                        <Typography variant="caption">
                                                            Unique device identifier
                                                        </Typography>
                                                    </Paper>
                                                </Grid>
                                                
                                                <Grid item xs={12} md={6}>
                                                    <Paper sx={{ p: 2 }}>
                                                        <Typography variant="subtitle1" gutterBottom>
                                                            Pre-Keys Generated
                                                        </Typography>
                                                        <Typography variant="h4" color="warning.main">
                                                            {keys.preKeys.length} (simulated)
                                                        </Typography>
                                                        <Typography variant="caption">
                                                            WASM implementation has bugs - showing simulation
                                                        </Typography>
                                                    </Paper>
                                                </Grid>
                                                
                                                <Grid item xs={12}>
                                                    <Alert severity="success">
                                                        <Typography variant="body2">
                                                            <strong>Success!</strong> You've created your cryptographic identity.
                                                            In a real app, you'd now upload your public keys to a server so others can find you.
                                                        </Typography>
                                                    </Alert>
                                                </Grid>
                                            </Grid>
                                        )}
                                    </Box>
                                )}
                            </>
                        )}
                    </CardContent>
                </Card>

                {/* What's Next */}
                {keys && (
                    <Alert severity="info" sx={{ mt: 3 }}>
                        <Typography variant="body1">
                            <strong>What's Next?</strong><br />
                            Now that you have your keys, the next step is to exchange them with someone else 
                            to establish a secure connection. Continue to the next lesson to learn about the X3DH key exchange! →
                        </Typography>
                    </Alert>
                )}
            </Box>
        </CryptoDemo>
    );
};

export default {
    title: 'Signal Protocol/Go WASM Tutorial/2. Generating Keys',
    component: CryptographyProvider,
    parameters: {
        docs: {
            description: {
                component: `
# Generating Cryptographic Keys

## What You'll Learn
- How to generate identity keys (your permanent ID)
- Understanding public vs private keys
- Creating pre-keys for offline messaging
- Digital signatures and verification

## Key Types Explained

### Identity Keys
- **Lifetime**: Permanent (never changes)
- **Purpose**: Your cryptographic identity
- **Algorithm**: Curve25519 (128-bit security)

### Pre-Keys
- **Lifetime**: One-time use
- **Purpose**: Allow offline message initiation
- **Quantity**: Generate 100+ at a time

### Signed Pre-Key
- **Lifetime**: Rotated periodically (e.g., weekly)
- **Purpose**: Authenticated key exchange
- **Special**: Includes your digital signature

## Security Best Practices
1. **Never share private keys**
2. **Store keys securely** (encrypted at rest)
3. **Rotate pre-keys regularly**
4. **Verify signatures always**
                `
            }
        }
    }
};

export const GeneratingKeys = () => (
    <CryptographyProvider>
        <GeneratingKeysStory />
    </CryptographyProvider>
);