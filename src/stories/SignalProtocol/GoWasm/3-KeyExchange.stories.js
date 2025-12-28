import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HandshakeIcon from '@mui/icons-material/Handshake';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import {
    Alert,
    Avatar,
    Box,
    Button, Card, CardContent,
    CircularProgress,
    Divider,
    Grid,
    Paper,
    Step,
    StepContent,
    StepLabel,
    Stepper,
    Typography
} from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { CodeDisplay, CryptoDemo, OperationStatus } from 'ui';
import { CryptographyProvider } from '../../components/Cryptography';

const KeyExchangeStory = () => {
    const [loading, setLoading] = useState(false);
    const [wasmReady, setWasmReady] = useState(false);
    const [error, setError] = useState('');
    const [activeStep, setActiveStep] = useState(0);
    const [alice, setAlice] = useState(null);
    const [bob, setBob] = useState(null);
    const [sessionEstablished, setSessionEstablished] = useState(false);
    
    const signalProtocolRef = useRef(null);

    useEffect(() => {
        loadWasm();
    }, []);

    const loadWasm = async () => {
        try {
            setLoading(true);
            const script = document.createElement('script');
            script.src = '/wasm/wasm_exec.js';
            document.head.appendChild(script);
            
            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
            });
            
            const go = new window.Go();
            const wasmResponse = await fetch('/wasm/signal.wasm');
            const wasmBuffer = await wasmResponse.arrayBuffer();
            const wasmModule = await WebAssembly.instantiate(wasmBuffer, go.importObject);
            
            go.run(wasmModule.instance);
            
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

    const generateAliceKeys = async () => {
        if (!signalProtocolRef.current) return;
        
        try {
            setLoading(true);
            setError('');
            
            const identity = await signalProtocolRef.current.generateIdentityKeyPair();
            const registrationId = signalProtocolRef.current.generateRegistrationId();
            
            // Simulate pre-keys due to WASM implementation bug
            const preKeys = Array.from({ length: 5 }, (_, i) => ({
                id: i,
                publicKey: `alice_prekey_${i}_public`,
                privateKey: `alice_prekey_${i}_private`
            }));
            const signedPreKey = {
                id: 0,
                publicKey: 'alice_signed_prekey_public',
                privateKey: 'alice_signed_prekey_private',
                signature: 'alice_signature',
                timestamp: Math.floor(Date.now() / 1000)
            };
            
            // Initialize Alice's session
            signalProtocolRef.current.initializeSession('alice');
            
            setAlice({
                id: 'alice',
                identity,
                registrationId,
                preKeys,
                signedPreKey
            });
            
            setActiveStep(1);
        } catch (err) {
            setError(`Failed to generate Alice's keys: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    const generateBobKeys = async () => {
        if (!signalProtocolRef.current || !alice) return;
        
        try {
            setLoading(true);
            
            const identity = await signalProtocolRef.current.generateIdentityKeyPair();
            const registrationId = signalProtocolRef.current.generateRegistrationId();
            
            // Simulate pre-keys due to WASM implementation bug
            const preKeys = Array.from({ length: 5 }, (_, i) => ({
                id: i,
                publicKey: `bob_prekey_${i}_public`,
                privateKey: `bob_prekey_${i}_private`
            }));
            const signedPreKey = {
                id: 0,
                publicKey: 'bob_signed_prekey_public',
                privateKey: 'bob_signed_prekey_private',
                signature: 'bob_signature',
                timestamp: Math.floor(Date.now() / 1000)
            };
            
            // Initialize Bob's session
            signalProtocolRef.current.initializeSession('bob');
            
            setBob({
                id: 'bob',
                identity,
                registrationId,
                preKeys,
                signedPreKey
            });
            
            setActiveStep(2);
        } catch (err) {
            setError(`Failed to generate Bob's keys: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    const performKeyExchange = async () => {
        if (!signalProtocolRef.current || !alice || !bob) return;
        
        try {
            setLoading(true);
            
            // Note: We skip processPreKeyBundle due to WASM implementation bugs
            // The processPreKeyBundle function causes crashes when called with any data
            // In a real implementation, this would perform X3DH key agreement
            
            // Instead, we simulate the successful key exchange process
            // This demonstrates the X3DH concept without crashing the WASM
            
            // Create Bob's pre-key bundle (what Alice would download from server)
            const bobBundle = {
                identityKey: bob.identity.publicKey,
                signedPreKeyPublic: bob.signedPreKey.publicKey,
                signedPreKeySignature: bob.signedPreKey.signature,
                preKeyPublic: bob.preKeys[0].publicKey,
                registrationId: bob.registrationId
            };
            
            // Create Alice's bundle for Bob
            const aliceBundle = {
                identityKey: alice.identity.publicKey,
                signedPreKeyPublic: alice.signedPreKey.publicKey,
                signedPreKeySignature: alice.signedPreKey.signature,
                preKeyPublic: alice.preKeys[0].publicKey,
                registrationId: alice.registrationId
            };
            
            // Simulate successful X3DH key agreement
            // In reality, both sides would perform 4 Diffie-Hellman operations:
            // DH1: Alice identity × Bob signed pre-key
            // DH2: Alice ephemeral × Bob identity  
            // DH3: Alice ephemeral × Bob signed pre-key
            // DH4: Alice ephemeral × Bob one-time pre-key (optional)
            
            
            setSessionEstablished(true);
            setActiveStep(3);
        } catch (err) {
            setError(`Key exchange failed: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    const steps = [
        {
            label: "Alice Generates Keys",
            description: "Alice creates her identity and pre-keys",
            action: generateAliceKeys
        },
        {
            label: "Bob Generates Keys",
            description: "Bob creates his identity and pre-keys",
            action: generateBobKeys
        },
        {
            label: "X3DH Key Exchange",
            description: "Alice and Bob exchange keys to establish secure session",
            action: performKeyExchange
        },
        {
            label: "Session Established",
            description: "Secure communication channel ready!",
            action: null
        }
    ];

    return (
        <CryptoDemo title="X3DH Key Exchange" icon={<HandshakeIcon />}>
            <Box sx={{ mb: 3 }}>
                <Alert severity="info" sx={{ mb: 3 }}>
                    <Typography variant="body1">
                        <strong>Lesson 3: The Secret Handshake (X3DH)</strong><br />
                        Learn how two people can establish a secure connection even if one is offline!
                        This is the magic that lets you send messages to someone who hasn't opened the app yet.
                    </Typography>
                </Alert>

                <Alert severity="warning" sx={{ mb: 3 }}>
                    <Typography variant="body2">
                        <strong>Implementation Note:</strong> The Go WASM implementation has bugs in the 
                        `processPreKeyBundle` function that cause crashes. This demo shows working identity 
                        key generation and simulates the X3DH key exchange process to demonstrate the concepts 
                        without crashing.
                    </Typography>
                </Alert>

                <Typography variant="h5" gutterBottom>
                    🤝 What is X3DH?
                </Typography>
                <Paper sx={{ p: 3, mb: 3 }}>
                    <Typography variant="body1" paragraph>
                        <strong>X3DH = Extended Triple Diffie-Hellman</strong>
                    </Typography>
                    <Typography variant="body1" paragraph>
                        Imagine Alice wants to send Bob a secret message, but Bob is camping without internet. 
                        X3DH is like Bob leaving a secure lockbox at the post office that only Alice can use to 
                        start a conversation.
                    </Typography>
                    
                    <Box sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, mt: 2 }}>
                        <Typography variant="h6" gutterBottom>The Three DH in X3DH:</Typography>
                        <Typography variant="body2" paragraph>
                            <strong>DH1:</strong> Alice's identity key + Bob's signed pre-key
                        </Typography>
                        <Typography variant="body2" paragraph>
                            <strong>DH2:</strong> Alice's ephemeral key + Bob's identity key
                        </Typography>
                        <Typography variant="body2" paragraph>
                            <strong>DH3:</strong> Alice's ephemeral key + Bob's signed pre-key
                        </Typography>
                        <Typography variant="body2">
                            <strong>DH4 (optional):</strong> Alice's ephemeral key + Bob's one-time pre-key
                        </Typography>
                    </Box>
                </Paper>

                <Typography variant="h5" gutterBottom>
                    📝 Step-by-Step Process
                </Typography>
                
                <OperationStatus loading={loading} error={error} success={sessionEstablished} />

                {wasmReady ? (
                    <Stepper activeStep={activeStep} orientation="vertical">
                        {steps.map((step, index) => (
                            <Step key={step.label}>
                                <StepLabel
                                    optional={
                                        index === 3 ? (
                                            <Typography variant="caption">Final step</Typography>
                                        ) : null
                                    }
                                >
                                    {step.label}
                                </StepLabel>
                                <StepContent>
                                    <Typography variant="body2" paragraph>
                                        {step.description}
                                    </Typography>
                                    
                                    {index === 0 && (
                                        <Card sx={{ mb: 2, bgcolor: 'primary.light' }}>
                                            <CardContent>
                                                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                                                    <Avatar sx={{ bgcolor: 'primary.main', mr: 2 }}>A</Avatar>
                                                    <Typography variant="h6">Alice's Setup</Typography>
                                                </Box>
                                                <CodeDisplay 
                                                    code={`// Alice generates her keys
const alice = {
  identity: generateIdentityKeyPair(),
  registrationId: generateRegistrationId(),
  preKeys: generatePreKeys(0, 100),
  signedPreKey: generateSignedPreKey(...)
};

// Alice uploads to server:
server.upload({
  identityPublicKey: alice.identity.publicKey,
  signedPreKey: alice.signedPreKey.public,
  preKeys: alice.preKeys.map(k => k.public)
});`}
                                                    language="javascript"
                                                />
                                                {alice && (
                                                    <Alert severity="success" sx={{ mt: 2 }}>
                                                        Alice's Registration ID: <strong>{alice.registrationId}</strong>
                                                    </Alert>
                                                )}
                                            </CardContent>
                                        </Card>
                                    )}
                                    
                                    {index === 1 && (
                                        <Card sx={{ mb: 2, bgcolor: 'secondary.light' }}>
                                            <CardContent>
                                                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                                                    <Avatar sx={{ bgcolor: 'secondary.main', mr: 2 }}>B</Avatar>
                                                    <Typography variant="h6">Bob's Setup</Typography>
                                                </Box>
                                                <CodeDisplay 
                                                    code={`// Bob does the same
const bob = {
  identity: generateIdentityKeyPair(),
  registrationId: generateRegistrationId(),
  preKeys: generatePreKeys(0, 100),
  signedPreKey: generateSignedPreKey(...)
};

// Bob's keys are also on the server
server.upload({
  identityPublicKey: bob.identity.publicKey,
  signedPreKey: bob.signedPreKey.public,
  preKeys: bob.preKeys.map(k => k.public)
});`}
                                                    language="javascript"
                                                />
                                                {bob && (
                                                    <Alert severity="success" sx={{ mt: 2 }}>
                                                        Bob's Registration ID: <strong>{bob.registrationId}</strong>
                                                    </Alert>
                                                )}
                                            </CardContent>
                                        </Card>
                                    )}
                                    
                                    {index === 2 && (
                                        <Card sx={{ mb: 2 }}>
                                            <CardContent>
                                                <Typography variant="h6" gutterBottom>
                                                    <SwapHorizIcon /> The Magic Happens!
                                                </Typography>
                                                <Grid container spacing={2}>
                                                    <Grid item xs={12} md={6}>
                                                        <Paper sx={{ p: 2, bgcolor: 'primary.light' }}>
                                                            <Typography variant="subtitle2" gutterBottom>
                                                                Alice's Side
                                                            </Typography>
                                                            <Typography variant="body2">
                                                                1. Downloads Bob's bundle<br />
                                                                2. Generates ephemeral key<br />
                                                                3. Performs 4 DH operations<br />
                                                                4. Derives shared secret
                                                            </Typography>
                                                        </Paper>
                                                    </Grid>
                                                    <Grid item xs={12} md={6}>
                                                        <Paper sx={{ p: 2, bgcolor: 'secondary.light' }}>
                                                            <Typography variant="subtitle2" gutterBottom>
                                                                Bob's Side
                                                            </Typography>
                                                            <Typography variant="body2">
                                                                1. Receives first message<br />
                                                                2. Gets Alice's ephemeral<br />
                                                                3. Performs same 4 DH ops<br />
                                                                4. Derives same secret!
                                                            </Typography>
                                                        </Paper>
                                                    </Grid>
                                                </Grid>
                                                
                                                <CodeDisplay 
                                                    code={`// The X3DH calculation (simplified)
const sharedSecret = KDF(
  DH(aliceIdentity, bobSignedPreKey) ||
  DH(aliceEphemeral, bobIdentity) ||
  DH(aliceEphemeral, bobSignedPreKey) ||
  DH(aliceEphemeral, bobOneTimePreKey)
);

// Both sides get the SAME secret!
// This is the foundation of their secure channel`}
                                                    language="javascript"
                                                    sx={{ mt: 2 }}
                                                />
                                            </CardContent>
                                        </Card>
                                    )}
                                    
                                    {index === 3 && sessionEstablished && (
                                        <Alert severity="success" icon={<CheckCircleIcon />}>
                                            <Typography variant="h6">
                                                🎉 Secure Session Established!
                                            </Typography>
                                            <Typography variant="body2" sx={{ mt: 1 }}>
                                                Alice and Bob now share a secret that:
                                            </Typography>
                                            <Box component="ul" sx={{ mt: 1 }}>
                                                <li>Nobody else knows (not even the server)</li>
                                                <li>Was created without ever meeting</li>
                                                <li>Works even if Bob was offline</li>
                                                <li>Provides perfect forward secrecy</li>
                                            </Box>
                                        </Alert>
                                    )}
                                    
                                    <Box sx={{ mb: 2, mt: 2 }}>
                                        {step.action && (
                                            <Button
                                                variant="contained"
                                                onClick={step.action}
                                                disabled={loading || index !== activeStep}
                                                sx={{ mr: 1 }}
                                            >
                                                {loading ? 'Processing...' : 'Execute'}
                                            </Button>
                                        )}
                                    </Box>
                                </StepContent>
                            </Step>
                        ))}
                    </Stepper>
                ) : (
                    <Box sx={{ textAlign: 'center', py: 3 }}>
                        <CircularProgress />
                        <Typography variant="body2" sx={{ mt: 2 }}>
                            Loading Signal Protocol...
                        </Typography>
                    </Box>
                )}

                {sessionEstablished && (
                    <>
                        <Divider sx={{ my: 3 }} />
                        
                        <Typography variant="h5" gutterBottom>
                            🔐 What Makes This Secure?
                        </Typography>
                        <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            Authentication
                                        </Typography>
                                        <Typography variant="body2">
                                            The identity keys prove you're really talking to who you think you are.
                                            The signed pre-key has Bob's signature, proving it came from him.
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            Forward Secrecy
                                        </Typography>
                                        <Typography variant="body2">
                                            The ephemeral keys are temporary and deleted after use.
                                            Even if someone steals keys later, they can't decrypt past messages.
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            Offline Capability
                                        </Typography>
                                        <Typography variant="body2">
                                            Bob doesn't need to be online! His pre-keys on the server
                                            let Alice start the conversation anytime.
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            Deniability
                                        </Typography>
                                        <Typography variant="body2">
                                            No digital signatures on messages means you can deny
                                            sending them - important for privacy!
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                        </Grid>
                        
                        <Alert severity="info" sx={{ mt: 3 }}>
                            <Typography variant="body1">
                                <strong>Ready for Messages!</strong><br />
                                Now that Alice and Bob have established a secure session, they can start
                                exchanging encrypted messages. Continue to the next lesson to see the
                                Double Ratchet in action! →
                            </Typography>
                        </Alert>
                    </>
                )}
            </Box>
        </CryptoDemo>
    );
};

export default {
    title: 'Signal Protocol/Go WASM Tutorial/3. Key Exchange (X3DH)',
    component: CryptographyProvider,
    parameters: {
        docs: {
            description: {
                component: `
# X3DH Key Exchange Protocol

## What You'll Learn
- How to establish secure communication without meeting
- The mathematics behind the "triple" Diffie-Hellman
- Why this works even when one party is offline
- Security properties of X3DH

## The Protocol Steps

### 1. **Setup Phase**
Both parties generate and upload their public keys to a server

### 2. **Bundle Retrieval**
Alice downloads Bob's "pre-key bundle" containing:
- Identity public key
- Signed pre-key
- One-time pre-key (if available)

### 3. **Key Agreement**
Alice performs multiple Diffie-Hellman operations to derive a shared secret

### 4. **Initial Message**
Alice sends her first message along with her ephemeral public key

### 5. **Bob's Derivation**
Bob uses the same DH operations to derive the identical shared secret

## Security Properties
- **Mutual Authentication**: Both parties verify each other's identity
- **Forward Secrecy**: Past messages stay secret even if keys are compromised
- **Asynchronous**: Works even when recipient is offline
- **Deniable**: Messages can be denied (no non-repudiation)
                `
            }
        }
    }
};

export const KeyExchange = () => (
    <CryptographyProvider>
        <KeyExchangeStory />
    </CryptographyProvider>
);