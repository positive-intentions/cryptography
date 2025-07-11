import React, { useState } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from '../components/shared';
import { 
  Button, 
  TextField, 
  Box, 
  Typography,
  Stack,
  Card,
  CardContent,
  CardHeader,
  Alert,
  Grid,
  Paper,
  Chip,
  Avatar,
  Divider,
  Step,
  StepLabel,
  Stepper
} from '@mui/material';
import { 
  Send, 
  VpnKey, 
  Security,
  Message,
  Person,
  SwapHoriz,
  CheckCircle
} from '@mui/icons-material';

export default {
  title: 'Cryptography/Use Cases/Secure Messaging',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'End-to-end encrypted messaging using hybrid cryptography (RSA + AES).',
      },
    },
  },
};

const HybridMessagingDemo = () => {
  const { 
    generateKeyPair,
    generateSymmetricKey,
    deserializePublicKey,
    deserializePrivateKey,
    deserializeSymmetricKey,
    encrypt,
    decrypt,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey
  } = useCryptography();
  
  const [step, setStep] = useState(0);
  const [alice, setAlice] = useState({ 
    keyPair: null, 
    message: '', 
    sessionKey: null,
    encryptedSessionKey: '',
    encryptedMessage: ''
  });
  const [bob, setBob] = useState({ 
    keyPair: null, 
    decryptedSessionKey: null,
    decryptedMessage: ''
  });
  const [loading, setLoading] = useState(false);

  const steps = [
    'Generate RSA key pairs',
    'Generate AES session key',
    'Exchange encrypted session key',
    'Send encrypted message',
    'Decrypt and read message'
  ];

  const generateKeyPairs = async () => {
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
      console.error('Error generating key pairs:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateSessionKey = async () => {
    setLoading(true);
    try {
      const sessionKey = await generateSymmetricKey();
      setAlice(prev => ({ ...prev, sessionKey }));
      setStep(2);
    } catch (error) {
      console.error('Error generating session key:', error);
    } finally {
      setLoading(false);
    }
  };

  const exchangeSessionKey = async () => {
    if (!alice.sessionKey || !bob.keyPair) return;
    
    setLoading(true);
    try {
      // Alice encrypts the session key with Bob's public key
      const bobPublicKey = await deserializePublicKey(bob.keyPair.publicKey);
      const sessionKeyStr = alice.sessionKey ? JSON.stringify(alice.sessionKey) : '';
      if (!sessionKeyStr) {
        throw new Error('No session key to encrypt');
      }
      const encryptedSessionKey = await encrypt(sessionKeyStr, bobPublicKey);
      
      setAlice(prev => ({ ...prev, encryptedSessionKey }));
      setStep(3);
    } catch (error) {
      console.error('Error exchanging session key:', error);
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async () => {
    if (!alice.message || !alice.sessionKey) return;
    
    setLoading(true);
    try {
      // Alice encrypts the message with the session key
      const sessionKey = await deserializeSymmetricKey(alice.sessionKey);
      const encryptedMessage = await encryptWithSymmetricKey(alice.message, sessionKey);
      
      setAlice(prev => ({ ...prev, encryptedMessage }));
      setStep(4);
    } catch (error) {
      console.error('Error encrypting message:', error);
    } finally {
      setLoading(false);
    }
  };

  const decryptMessage = async () => {
    if (!alice.encryptedSessionKey || !alice.encryptedMessage || !bob.keyPair) return;
    
    setLoading(true);
    try {
      // Step 1: Bob decrypts the session key with his private key
      const bobPrivateKey = await deserializePrivateKey(bob.keyPair.privateKey);
      const decryptedSessionKeyStr = await decrypt(alice.encryptedSessionKey, bobPrivateKey);
      
      let decryptedSessionKey;
      try {
        decryptedSessionKey = JSON.parse(decryptedSessionKeyStr);
      } catch (error) {
        console.error('Error parsing decrypted session key:', error);
        throw new Error('Failed to parse decrypted session key');
      }
      
      // Step 2: Bob uses the session key to decrypt the message
      const sessionKey = await deserializeSymmetricKey(decryptedSessionKey);
      const decryptedMessage = await decryptWithSymmetricKey(alice.encryptedMessage, sessionKey);
      
      setBob(prev => ({ 
        ...prev, 
        decryptedSessionKey,
        decryptedMessage 
      }));
    } catch (error) {
      console.error('Error decrypting message:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Hybrid Cryptography Messaging"
      description="Secure messaging using RSA for key exchange and AES for message encryption."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          <Typography variant="body2">
            <strong>Hybrid Approach:</strong> This demo shows how real-world encrypted messaging works. 
            RSA encrypts a randomly generated AES key, then AES encrypts the actual message. 
            This combines RSA's security with AES's speed.
          </Typography>
        </Alert>

        <Stepper activeStep={step} orientation="vertical">
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        <OperationStatus loading={loading} />

        {/* Step 0: Generate Key Pairs */}
        {step === 0 && (
          <Card>
            <CardHeader
              title="Initialize Participants"
              subheader="Generate RSA key pairs for Alice and Bob"
            />
            <CardContent>
              <Button
                variant="contained"
                onClick={generateKeyPairs}
                disabled={loading}
                startIcon={<VpnKey />}
                size="large"
              >
                Generate RSA Key Pairs
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 1: Generate Session Key */}
        {step === 1 && (
          <Card>
            <CardHeader
              title="Create Session Key"
              subheader="Alice generates a symmetric AES key for this conversation"
            />
            <CardContent>
              <Button
                variant="contained"
                onClick={generateSessionKey}
                disabled={loading}
                startIcon={<Security />}
                size="large"
              >
                Generate AES Session Key
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 2: Exchange Session Key */}
        {step === 2 && (
          <Card>
            <CardHeader
              title="Exchange Session Key"
              subheader="Alice encrypts the session key with Bob's public key"
            />
            <CardContent>
              <Button
                variant="contained"
                onClick={exchangeSessionKey}
                disabled={loading}
                startIcon={<SwapHoriz />}
                size="large"
              >
                Encrypt & Send Session Key
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 3: Send Message */}
        {step === 3 && (
          <Card>
            <CardHeader
              title="Send Encrypted Message"
              subheader="Alice encrypts her message with the session key"
            />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Alice's Message"
                  value={alice.message}
                  onChange={(e) => setAlice(prev => ({ ...prev, message: e.target.value }))}
                  multiline
                  rows={3}
                  fullWidth
                  placeholder="Type your secret message..."
                />
                <Button
                  variant="contained"
                  onClick={sendMessage}
                  disabled={loading || !alice.message}
                  startIcon={<Send />}
                  size="large"
                >
                  Encrypt & Send Message
                </Button>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Step 4: Decrypt Message */}
        {step === 4 && (
          <Card>
            <CardHeader
              title="Decrypt Message"
              subheader="Bob receives and decrypts the message"
            />
            <CardContent>
              <Stack spacing={2}>
                <Button
                  variant="contained"
                  onClick={decryptMessage}
                  disabled={loading}
                  startIcon={<Message />}
                  size="large"
                >
                  Decrypt Message
                </Button>

                {bob.decryptedMessage && (
                  <Alert severity="success">
                    <Typography variant="h6" gutterBottom>
                      🎉 Message Decrypted Successfully!
                    </Typography>
                    <Typography variant="body1">
                      <strong>Alice sent:</strong> "{alice.message}"
                    </Typography>
                    <Typography variant="body1">
                      <strong>Bob received:</strong> "{bob.decryptedMessage}"
                    </Typography>
                  </Alert>
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Show encryption details */}
        {step > 0 && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1} mb={2}>
                  <Avatar sx={{ bgcolor: 'primary.main' }}>
                    <Person />
                  </Avatar>
                  <Typography variant="h6">Alice (Sender)</Typography>
                </Stack>
                
                {alice.sessionKey && (
                  <CodeDisplay
                    code={alice.sessionKey ? JSON.stringify(alice.sessionKey, null, 2) : 'No session key available'}
                    label="Session Key (AES)"
                    secret={true}
                    maxHeight="100px"
                  />
                )}
                
                {alice.encryptedSessionKey && (
                  <CodeDisplay
                    code={alice.encryptedSessionKey}
                    label="Encrypted Session Key (RSA)"
                    maxHeight="100px"
                  />
                )}
                
                {alice.encryptedMessage && (
                  <CodeDisplay
                    code={alice.encryptedMessage ? JSON.stringify(alice.encryptedMessage, null, 2) : 'No encrypted message available'}
                    label="Encrypted Message (AES)"
                    maxHeight="100px"
                  />
                )}
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" alignItems="center" spacing={1} mb={2}>
                  <Avatar sx={{ bgcolor: 'secondary.main' }}>
                    <Person />
                  </Avatar>
                  <Typography variant="h6">Bob (Receiver)</Typography>
                </Stack>
                
                {bob.decryptedSessionKey && (
                  <CodeDisplay
                    code={bob.decryptedSessionKey ? JSON.stringify(bob.decryptedSessionKey, null, 2) : 'No decrypted session key available'}
                    label="Decrypted Session Key"
                    secret={true}
                    maxHeight="100px"
                  />
                )}
                
                {bob.decryptedMessage && (
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Final Message:</strong> {bob.decryptedMessage}
                    </Typography>
                  </Alert>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}

        <Divider />

        <Box>
          <Typography variant="h6" gutterBottom>
            Why Hybrid Cryptography?
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                <VpnKey color="primary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="subtitle2" gutterBottom>
                  RSA for Key Exchange
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Secure, but slow for large data
                </Typography>
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                <Security color="secondary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="subtitle2" gutterBottom>
                  AES for Messages
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Fast encryption for any size data
                </Typography>
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                <CheckCircle color="success" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="subtitle2" gutterBottom>
                  Best of Both
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Secure and efficient for all use cases
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      </Stack>
    </CryptoDemo>
  );
};

export const Default = () => (
  <CryptographyProvider>
    <HybridMessagingDemo />
  </CryptographyProvider>
);

const GroupMessagingDemo = () => {
  const { 
    generateSymmetricKey,
    deserializeSymmetricKey,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey
  } = useCryptography();
  
  const [groupKey, setGroupKey] = useState(null);
  const [participants, setParticipants] = useState([
    { id: 1, name: 'Alice', color: 'primary' },
    { id: 2, name: 'Bob', color: 'secondary' },
    { id: 3, name: 'Charlie', color: 'success' }
  ]);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [selectedSender, setSelectedSender] = useState(1);
  const [loading, setLoading] = useState(false);

  const createGroup = async () => {
    setLoading(true);
    try {
      const key = await generateSymmetricKey();
      setGroupKey(key);
    } catch (error) {
      console.error('Error creating group:', error);
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async () => {
    if (!groupKey || !newMessage) return;
    
    setLoading(true);
    try {
      const key = await deserializeSymmetricKey(groupKey);
      const encrypted = await encryptWithSymmetricKey(newMessage, key);
      
      const message = {
        id: Date.now(),
        senderId: selectedSender,
        senderName: participants.find(p => p.id === selectedSender)?.name,
        content: newMessage,
        encrypted: encrypted,
        timestamp: new Date().toLocaleTimeString()
      };
      
      setMessages(prev => [...prev, message]);
      setNewMessage('');
    } catch (error) {
      console.error('Error sending message:', error);
    } finally {
      setLoading(false);
    }
  };

  const decryptMessage = async (messageId) => {
    if (!groupKey) return;
    
    setLoading(true);
    try {
      const key = await deserializeSymmetricKey(groupKey);
      const message = messages.find(m => m.id === messageId);
      
      if (message && !message.decrypted) {
        const decrypted = await decryptWithSymmetricKey(message.encrypted, key);
        
        setMessages(prev => prev.map(m => 
          m.id === messageId ? { ...m, decrypted } : m
        ));
      }
    } catch (error) {
      console.error('Error decrypting message:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Group Messaging with Shared Key"
      description="Multiple participants sharing a single symmetric key for group conversations."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          <Typography variant="body2">
            In this simplified group messaging demo, all participants share the same AES key. 
            In real applications, key distribution would be more complex and secure.
          </Typography>
        </Alert>

        {!groupKey && (
          <Button
            variant="contained"
            onClick={createGroup}
            disabled={loading}
            startIcon={<Security />}
            size="large"
          >
            Create Encrypted Group
          </Button>
        )}

        {groupKey && (
          <Stack spacing={2}>
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Group Participants
              </Typography>
              <Stack direction="row" spacing={1}>
                {participants.map(participant => (
                  <Chip
                    key={participant.id}
                    label={participant.name}
                    color={participant.color}
                    variant="outlined"
                    avatar={<Avatar>{participant.name[0]}</Avatar>}
                  />
                ))}
              </Stack>
            </Paper>

            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Send Message
              </Typography>
              <Stack spacing={2}>
                <TextField
                  select
                  label="Send as"
                  value={selectedSender}
                  onChange={(e) => setSelectedSender(Number(e.target.value))}
                  SelectProps={{ native: true }}
                >
                  {participants.map(p => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </TextField>
                
                <TextField
                  label="Message"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  fullWidth
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                />
                
                <Button
                  variant="contained"
                  onClick={sendMessage}
                  disabled={loading || !newMessage}
                  startIcon={<Send />}
                >
                  Send Encrypted Message
                </Button>
              </Stack>
            </Paper>

            {messages.length > 0 && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Group Messages
                </Typography>
                <Stack spacing={1}>
                  {messages.map(message => (
                    <Card key={message.id} variant="outlined">
                      <CardContent sx={{ p: 2 }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                          <Typography variant="caption" color="text.secondary">
                            {message.senderName} • {message.timestamp}
                          </Typography>
                          {!message.decrypted && (
                            <Button
                              size="small"
                              onClick={() => decryptMessage(message.id)}
                              disabled={loading}
                            >
                              Decrypt
                            </Button>
                          )}
                        </Stack>
                        
                        {message.decrypted ? (
                          <Alert severity="success" sx={{ py: 1 }}>
                            <Typography variant="body2">
                              {message.decrypted}
                            </Typography>
                          </Alert>
                        ) : (
                          <CodeDisplay
                            code={message.encrypted ? JSON.stringify(message.encrypted, null, 2) : 'No encrypted message available'}
                            label="Encrypted Message"
                            maxHeight="80px"
                          />
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              </Paper>
            )}
          </Stack>
        )}

        <OperationStatus loading={loading} />
      </Stack>
    </CryptoDemo>
  );
};

export const GroupMessaging = () => (
  <CryptographyProvider>
    <GroupMessagingDemo />
  </CryptographyProvider>
);