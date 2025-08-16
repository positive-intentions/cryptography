import React, { useState, useEffect } from 'react';
import { 
    Box, Typography, Card, CardContent, Alert, Paper, 
    Grid, Accordion, AccordionSummary, AccordionDetails,
    List, ListItem, ListItemText, Chip, Divider, Button,
    TextField, LinearProgress, Table, TableBody, TableCell,
    TableContainer, TableHead, TableRow, Badge
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import ShuffleIcon from '@mui/icons-material/Shuffle';
import HealingIcon from '@mui/icons-material/Healing';
import SpeedIcon from '@mui/icons-material/Speed';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { CryptographyProvider, useCryptography } from '../../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from 'ui';

const AdvancedConceptsStory = () => {
    const [expandedPanel, setExpandedPanel] = useState('panel1');

    const handleAccordionChange = (panel) => (event, isExpanded) => {
        setExpandedPanel(isExpanded ? panel : false);
    };

    return (
        <CryptoDemo title="Advanced Signal Protocol Concepts" icon={<SecurityIcon />}>
            <Box sx={{ mb: 3 }}>
                <Alert severity="success" sx={{ mb: 3 }}>
                    <Typography variant="body1">
                        <strong>Lesson 5: Master-Level Concepts</strong><br />
                        You've learned the basics! Now let's explore the advanced features that make
                        the Signal Protocol incredibly robust in real-world conditions.
                    </Typography>
                </Alert>

                <Typography variant="h5" gutterBottom>
                    🎓 What We'll Cover
                </Typography>
                <Grid container spacing={2} sx={{ mb: 3 }}>
                    <Grid item xs={12} sm={6} md={3}>
                        <Card sx={{ textAlign: 'center', bgcolor: 'primary.light' }}>
                            <CardContent>
                                <ShuffleIcon fontSize="large" color="primary" />
                                <Typography variant="h6">Out-of-Order Messages</Typography>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                        <Card sx={{ textAlign: 'center', bgcolor: 'secondary.light' }}>
                            <CardContent>
                                <HealingIcon fontSize="large" color="secondary" />
                                <Typography variant="h6">Self-Healing</Typography>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                        <Card sx={{ textAlign: 'center', bgcolor: 'success.light' }}>
                            <CardContent>
                                <TrendingUpIcon fontSize="large" color="success" />
                                <Typography variant="h6">Key Rotation</Typography>
                            </CardContent>
                        </Card>
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                        <Card sx={{ textAlign: 'center', bgcolor: 'warning.light' }}>
                            <CardContent>
                                <SpeedIcon fontSize="large" color="warning" />
                                <Typography variant="h6">Performance</Typography>
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>

                <Accordion expanded={expandedPanel === 'panel1'} onChange={handleAccordionChange('panel1')}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">
                            <ShuffleIcon sx={{ mr: 1 }} /> Out-of-Order Message Handling
                        </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body1" paragraph>
                            Real networks are messy! Messages can arrive late, duplicated, or out of order.
                            The Signal Protocol handles this gracefully without losing security.
                        </Typography>
                        
                        <Alert severity="info" sx={{ mb: 2 }}>
                            <Typography variant="body2">
                                <strong>The Problem:</strong> Alice sends messages 1, 2, 3, but Bob receives 1, 3, 2.
                                Traditional encryption would fail, but Signal Protocol just works!
                            </Typography>
                        </Alert>

                        <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                                    <Typography variant="subtitle1" gutterBottom>
                                        Message Key Storage
                                    </Typography>
                                    <CodeDisplay 
                                        code={`// Instead of deleting message keys immediately:
messageKeys = {
  1: "key_for_message_1",
  2: "key_for_message_2", 
  3: "key_for_message_3",
  // ... keep for reasonable window
}

// When message 3 arrives first:
if (messageKeys[3]) {
  decrypt(msg3, messageKeys[3])
  delete messageKeys[3]  // Clean up
}

// Message 2 arrives later - still works!`}
                                        language="javascript"
                                    />
                                </Paper>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2 }}>
                                    <Typography variant="subtitle1" gutterBottom>
                                        Chain Key Management
                                    </Typography>
                                    <List dense>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Skipped Messages" 
                                                secondary="Generate keys for missing message numbers"
                                            />
                                        </ListItem>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Storage Limits" 
                                                secondary="Keep keys for reasonable window (e.g., 1000 messages)"
                                            />
                                        </ListItem>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Cleanup Policy" 
                                                secondary="Delete old keys to prevent memory bloat"
                                            />
                                        </ListItem>
                                    </List>
                                </Paper>
                            </Grid>
                        </Grid>

                        <Alert severity="warning" sx={{ mt: 2 }}>
                            <Typography variant="body2">
                                <strong>Trade-off:</strong> More memory usage vs better reliability. 
                                Production apps balance this with configurable limits.
                            </Typography>
                        </Alert>
                    </AccordionDetails>
                </Accordion>

                <Accordion expanded={expandedPanel === 'panel2'} onChange={handleAccordionChange('panel2')}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">
                            <HealingIcon sx={{ mr: 1 }} /> Self-Healing Properties
                        </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body1" paragraph>
                            Even if an attacker compromises your keys, the Double Ratchet can "heal" itself
                            and restore security! This is called "future secrecy" or "post-compromise security."
                        </Typography>

                        <Grid container spacing={2} sx={{ mb: 2 }}>
                            <Grid item xs={12} md={4}>
                                <Card sx={{ bgcolor: 'error.light', height: '100%' }}>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            🚨 Compromise Happens
                                        </Typography>
                                        <Typography variant="body2">
                                            Attacker steals Alice's current session keys
                                            through malware or physical access.
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={4}>
                                <Card sx={{ bgcolor: 'warning.light', height: '100%' }}>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            🔄 Healing Begins
                                        </Typography>
                                        <Typography variant="body2">
                                            Next message from Bob triggers new DH exchange,
                                            generating fresh root and chain keys.
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={4}>
                                <Card sx={{ bgcolor: 'success.light', height: '100%' }}>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom>
                                            ✅ Security Restored
                                        </Typography>
                                        <Typography variant="body2">
                                            New messages use fresh keys unknown to attacker.
                                            Conversation is secure again!
                                        </Typography>
                                    </CardContent>
                                </Card>
                            </Grid>
                        </Grid>

                        <CodeDisplay 
                            code={`// Self-healing through DH ratchet step
function dhRatchetReceive(state, bobPublicKey) {
  // Generate new ephemeral key pair
  state.ephemeralKeyPair = generateKeyPair()
  
  // Perform DH with received public key
  const dhOutput = DH(state.ephemeralKeyPair.private, bobPublicKey)
  
  // Update root key and create new chains
  [state.rootKey, state.receivingChain] = HKDF(state.rootKey, dhOutput)
  
  // Old compromised keys are now useless!
  // Fresh security established
  
  return state
}`}
                            language="javascript"
                        />

                        <Alert severity="success" sx={{ mt: 2 }}>
                            <Typography variant="body2">
                                <strong>Amazing Fact:</strong> Signal Protocol can recover from key compromise
                                automatically, without users even knowing it happened!
                            </Typography>
                        </Alert>
                    </AccordionDetails>
                </Accordion>

                <Accordion expanded={expandedPanel === 'panel3'} onChange={handleAccordionChange('panel3')}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">
                            <TrendingUpIcon sx={{ mr: 1 }} /> Key Rotation and Management
                        </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body1" paragraph>
                            Keys don't last forever! The Signal Protocol includes sophisticated key rotation
                            to maintain long-term security even in active conversations.
                        </Typography>

                        <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2 }}>
                                    <Typography variant="subtitle1" gutterBottom color="primary">
                                        Pre-Key Rotation
                                    </Typography>
                                    <CodeDisplay 
                                        code={`// Pre-keys are consumed and need replenishment
if (preKeyStore.count() < 50) {
  const newPreKeys = generatePreKeys(
    lastPreKeyId + 1,
    100  // Generate 100 new ones
  )
  
  preKeyStore.storePreKeys(newPreKeys)
  server.uploadPreKeys(newPreKeys.map(k => k.public))
  
  console.log("Pre-key pool replenished")
}`}
                                        language="javascript"
                                    />
                                    <List dense sx={{ mt: 1 }}>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Frequency: As needed"
                                                secondary="When pre-key count drops below threshold"
                                            />
                                        </ListItem>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Batch Size: ~100 keys"
                                                secondary="Balance between server load and availability"
                                            />
                                        </ListItem>
                                    </List>
                                </Paper>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2 }}>
                                    <Typography variant="subtitle1" gutterBottom color="secondary">
                                        Signed Pre-Key Rotation
                                    </Typography>
                                    <CodeDisplay 
                                        code={`// Signed pre-keys rotate on schedule
const WEEK = 7 * 24 * 60 * 60 * 1000
if (Date.now() - signedPreKey.timestamp > WEEK) {
  
  const newSignedPreKey = generateSignedPreKey(
    identityKeyPair,
    ++signedPreKeyId
  )
  
  signedPreKeyStore.store(newSignedPreKey)
  server.uploadSignedPreKey(newSignedPreKey)
  
  // Keep old one briefly for in-flight messages
  setTimeout(() => {
    signedPreKeyStore.remove(oldSignedPreKey.id)
  }, 24 * 60 * 60 * 1000) // 24 hours
}`}
                                        language="javascript"
                                    />
                                    <List dense sx={{ mt: 1 }}>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Frequency: Weekly"
                                                secondary="Regular rotation for long-term security"
                                            />
                                        </ListItem>
                                        <ListItem>
                                            <ListItemText 
                                                primary="Grace Period: 24h"
                                                secondary="Keep old key briefly for late messages"
                                            />
                                        </ListItem>
                                    </List>
                                </Paper>
                            </Grid>
                        </Grid>

                        <Divider sx={{ my: 2 }} />

                        <Typography variant="subtitle1" gutterBottom>
                            Identity Key Lifecycle
                        </Typography>
                        <Alert severity="warning" sx={{ mb: 2 }}>
                            <Typography variant="body2">
                                Identity keys are <strong>permanent</strong> and should never be rotated casually.
                                Changing identity keys is like changing your identity - it breaks trust with all contacts!
                            </Typography>
                        </Alert>

                        <Box sx={{ pl: 2 }}>
                            <Typography variant="body2" paragraph>
                                <strong>When to rotate identity keys:</strong>
                            </Typography>
                            <List dense>
                                <ListItem>
                                    <ListItemText primary="✅ Device compromise confirmed" />
                                </ListItem>
                                <ListItem>
                                    <ListItemText primary="✅ Upgrading to new device" />
                                </ListItem>
                                <ListItem>
                                    <ListItemText primary="✅ Cryptographic algorithm upgrade" />
                                </ListItem>
                                <ListItem>
                                    <ListItemText primary="❌ Regular maintenance (never!)" />
                                </ListItem>
                            </List>
                        </Box>
                    </AccordionDetails>
                </Accordion>

                <Accordion expanded={expandedPanel === 'panel4'} onChange={handleAccordionChange('panel4')}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">
                            <SpeedIcon sx={{ mr: 1 }} /> Performance and Optimization
                        </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography variant="body1" paragraph>
                            Real-world messaging apps need to be fast! Here are the key performance considerations
                            and optimizations used in production Signal Protocol implementations.
                        </Typography>

                        <Grid container spacing={2} sx={{ mb: 2 }}>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom color="success.main">
                                            ⚡ Performance Wins
                                        </Typography>
                                        <List dense>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="Curve25519 Operations"
                                                    secondary="~0.1ms on modern devices"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="AES-256 Encryption"
                                                    secondary="Hardware acceleration available"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="Message Key Derivation"
                                                    secondary="Simple HMAC operations"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="Batch Operations"
                                                    secondary="Process multiple messages together"
                                                />
                                            </ListItem>
                                        </List>
                                    </CardContent>
                                </Card>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Card>
                                    <CardContent>
                                        <Typography variant="h6" gutterBottom color="warning.main">
                                            🐌 Performance Costs
                                        </Typography>
                                        <List dense>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="Key Storage"
                                                    secondary="Must store skipped message keys"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="DH Ratchet Steps"
                                                    secondary="New key generation on sends"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="State Serialization"
                                                    secondary="Persist ratchet state to disk"
                                                />
                                            </ListItem>
                                            <ListItem>
                                                <ListItemText 
                                                    primary="Memory Usage"
                                                    secondary="Grows with conversation length"
                                                />
                                            </ListItem>
                                        </List>
                                    </CardContent>
                                </Card>
                            </Grid>
                        </Grid>

                        <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                            <Typography variant="subtitle1" gutterBottom>
                                Real-World Benchmarks (Go WASM Implementation)
                            </Typography>
                            <Grid container spacing={2}>
                                <Grid item xs={6} sm={3}>
                                    <Box sx={{ textAlign: 'center' }}>
                                        <Typography variant="h4" color="primary">~50ms</Typography>
                                        <Typography variant="caption">Key Generation</Typography>
                                    </Box>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                    <Box sx={{ textAlign: 'center' }}>
                                        <Typography variant="h4" color="primary">~20ms</Typography>
                                        <Typography variant="caption">Session Setup</Typography>
                                    </Box>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                    <Box sx={{ textAlign: 'center' }}>
                                        <Typography variant="h4" color="primary">~2ms</Typography>
                                        <Typography variant="caption">Encrypt Message</Typography>
                                    </Box>
                                </Grid>
                                <Grid item xs={6} sm={3}>
                                    <Box sx={{ textAlign: 'center' }}>
                                        <Typography variant="h4" color="primary">~1ms</Typography>
                                        <Typography variant="caption">Decrypt Message</Typography>
                                    </Box>
                                </Grid>
                            </Grid>
                        </Paper>

                        <CodeDisplay 
                            code={`// Optimization: Lazy key derivation
class MessageKeyCache {
  constructor(chainKey, maxSkip = 1000) {
    this.chainKey = chainKey
    this.cache = new Map()
    this.maxSkip = maxSkip
  }
  
  getMessageKey(messageNumber) {
    if (this.cache.has(messageNumber)) {
      const key = this.cache.get(messageNumber)
      this.cache.delete(messageNumber)  // Use once
      return key
    }
    
    // Derive missing keys up to messageNumber
    while (this.currentNumber <= messageNumber) {
      if (this.cache.size > this.maxSkip) {
        throw new Error("Too many skipped messages")
      }
      
      const msgKey = HMAC(this.chainKey, "MessageKey")
      this.cache.set(this.currentNumber, msgKey)
      this.chainKey = HMAC(this.chainKey, "ChainKey") 
      this.currentNumber++
    }
    
    return this.getMessageKey(messageNumber)
  }
}`}
                            language="javascript"
                            sx={{ mt: 2 }}
                        />
                    </AccordionDetails>
                </Accordion>

                <Alert severity="success" sx={{ mt: 3 }}>
                    <Typography variant="h6" gutterBottom>
                        🎉 Congratulations! You're Now a Signal Protocol Expert!
                    </Typography>
                    <Typography variant="body1" paragraph>
                        You've learned everything from basic key generation to advanced concepts like
                        self-healing and performance optimization. You now understand one of the most
                        important cryptographic protocols in the world!
                    </Typography>
                    <Typography variant="body2">
                        <strong>What's Next?</strong> Try implementing your own messaging app, contribute to
                        open source projects, or dive deeper into cryptographic research. The skills you've
                        learned here are the foundation of modern digital privacy.
                    </Typography>
                </Alert>

                <Paper sx={{ p: 3, mt: 3, bgcolor: 'primary.light' }}>
                    <Typography variant="h6" gutterBottom>
                        📚 Further Reading
                    </Typography>
                    <Grid container spacing={2}>
                        <Grid item xs={12} md={6}>
                            <List>
                                <ListItem>
                                    <ListItemText 
                                        primary="Signal Protocol Specifications"
                                        secondary="Official technical documentation"
                                    />
                                </ListItem>
                                <ListItem>
                                    <ListItemText 
                                        primary="Double Ratchet Algorithm"
                                        secondary="Deep dive into the ratchet mechanism"
                                    />
                                </ListItem>
                                <ListItem>
                                    <ListItemText 
                                        primary="X3DH Key Agreement Protocol"
                                        secondary="Asynchronous key exchange details"
                                    />
                                </ListItem>
                            </List>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <List>
                                <ListItem>
                                    <ListItemText 
                                        primary="Cryptographic Engineering"
                                        secondary="Building secure systems at scale"
                                    />
                                </ListItem>
                                <ListItem>
                                    <ListItemText 
                                        primary="Post-Quantum Cryptography"
                                        secondary="Future-proofing against quantum computers"
                                    />
                                </ListItem>
                                <ListItem>
                                    <ListItemText 
                                        primary="Security Protocols"
                                        secondary="TLS, WireGuard, and other protocols"
                                    />
                                </ListItem>
                            </List>
                        </Grid>
                    </Grid>
                </Paper>
            </Box>
        </CryptoDemo>
    );
};

export default {
    title: 'Signal Protocol/Go WASM Tutorial/5. Advanced Concepts',
    component: CryptographyProvider,
    parameters: {
        docs: {
            description: {
                component: `
# Advanced Signal Protocol Concepts

## Master-Level Topics Covered

### Out-of-Order Message Handling
- Network realities and message ordering
- Skipped message key management
- Storage optimization strategies

### Self-Healing Properties
- Post-compromise security guarantees
- Automatic recovery mechanisms
- Future secrecy through DH ratcheting

### Key Rotation Strategies
- Pre-key pool management
- Signed pre-key lifecycle
- Identity key considerations

### Performance Optimization
- Real-world benchmarks
- Memory management
- Cryptographic acceleration

## Production Considerations

### Scalability
- Multi-device synchronization
- Group messaging extensions
- Server-side key management

### Security Analysis
- Formal verification methods
- Attack surface analysis
- Threat model validation

### Implementation Quality
- Constant-time algorithms
- Side-channel resistance
- Error handling strategies

## The Bigger Picture
Understanding these concepts prepares you for:
- Implementing secure messaging systems
- Security auditing and analysis  
- Advanced cryptographic research
- Privacy-preserving technologies
                `
            }
        }
    }
};

export const AdvancedConcepts = () => (
    <CryptographyProvider>
        <AdvancedConceptsStory />
    </CryptographyProvider>
);