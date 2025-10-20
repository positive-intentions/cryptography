/**
 * MLS (Message Layer Security) Demo
 * Interactive demonstration of end-to-end encrypted group messaging
 */

import React, { useState, useEffect } from 'react';
import { MLSManager } from '../../crypto/MLS/MLSManager.tsx';
import { ThemeProvider, Container, Paper, Typography, Button, TextField, Box, Stack, Chip, Alert } from 'ui';

export default {
  title: 'MLS/MLSDemo',
  parameters: {
    layout: 'fullscreen',
  },
};

const MLSDemoApp = () => {
  const [aliceManager, setAliceManager] = useState(null);
  const [bobManager, setBobManager] = useState(null);
  const [charlieManager, setCharlieManager] = useState(null);

  const [groupId, setGroupId] = useState('my-secure-group');
  const [aliceMessages, setAliceMessages] = useState([]);
  const [bobMessages, setBobMessages] = useState([]);
  const [charlieMessages, setCharlieMessages] = useState([]);

  const [aliceInput, setAliceInput] = useState('');
  const [bobInput, setBobInput] = useState('');
  const [charlieInput, setCharlieInput] = useState('');

  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('Not initialized');
  const [keyInfo, setKeyInfo] = useState(null);

  const addLog = (message) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${message}`]);
  };

  // Initialize MLS managers
  const initializeManagers = async () => {
    try {
      setStatus('Initializing...');
      addLog('🔐 Initializing MLS managers...');

      // Create managers
      const alice = new MLSManager('alice@example.com');
      const bob = new MLSManager('bob@example.com');
      const charlie = new MLSManager('charlie@example.com');

      // Initialize them
      await alice.initialize();
      addLog('✅ Alice initialized');

      await bob.initialize();
      addLog('✅ Bob initialized');

      await charlie.initialize();
      addLog('✅ Charlie initialized');

      setAliceManager(alice);
      setBobManager(bob);
      setCharlieManager(charlie);

      setStatus('Initialized');
      addLog('✅ All managers initialized successfully');
    } catch (err) {
      console.error('Initialization error:', err);
      setError(`Initialization failed: ${err.message}`);
      addLog(`❌ Initialization failed: ${err.message}`);
    }
  };

  // Create group and add members
  const createGroup = async () => {
    try {
      if (!aliceManager || !bobManager || !charlieManager) {
        throw new Error('Managers not initialized');
      }

      setStatus('Creating group...');
      addLog(`📝 Creating group: ${groupId}`);

      // Alice creates the group
      await aliceManager.createGroup(groupId);
      addLog('✅ Alice created the group');

      // Bob and Charlie generate key packages
      const bobKeyPackage = await bobManager.generateKeyPackage();
      const charlieKeyPackage = await charlieManager.generateKeyPackage();
      addLog('🔑 Bob and Charlie generated key packages');

      // Alice adds Bob and Charlie to the group
      const { welcome: bobWelcome } = await aliceManager.addMembers(groupId, [bobKeyPackage]);
      await bobManager.processWelcome(bobWelcome);
      addLog('✅ Bob joined the group');

      const { welcome: charlieWelcome } = await aliceManager.addMembers(groupId, [charlieKeyPackage]);
      await charlieManager.processWelcome(charlieWelcome);
      addLog('✅ Charlie joined the group');

      setStatus('Group ready');
      addLog('🎉 Group setup complete! Ready for encrypted messaging.');

      // Get and display key info
      const aliceKeyInfo = await aliceManager.getGroupKeyInfo(groupId);
      setKeyInfo(aliceKeyInfo);
      addLog(`🔑 Group Key: ${aliceKeyInfo.keyId}`);
    } catch (err) {
      console.error('Group creation error:', err);
      setError(`Group creation failed: ${err.message}`);
      addLog(`❌ Group creation failed: ${err.message}`);
    }
  };

  // Alice sends a message
  const sendAliceMessage = async () => {
    try {
      if (!aliceInput.trim()) return;

      const envelope = await aliceManager.encryptMessage(groupId, aliceInput);
      addLog(`📤 Alice sent encrypted message`);

      // Add to Alice's view
      setAliceMessages((prev) => [...prev, { from: 'Alice', text: aliceInput, encrypted: false }]);

      // Bob and Charlie decrypt
      const bobDecrypted = await bobManager.decryptMessage(envelope);
      setBobMessages((prev) => [...prev, { from: 'Alice', text: bobDecrypted, encrypted: true }]);

      const charlieDecrypted = await charlieManager.decryptMessage(envelope);
      setCharlieMessages((prev) => [...prev, { from: 'Alice', text: charlieDecrypted, encrypted: true }]);

      addLog(`✅ Message delivered to Bob and Charlie`);
      setAliceInput('');
    } catch (err) {
      console.error('Send error:', err);
      setError(`Send failed: ${err.message}`);
      addLog(`❌ Send failed: ${err.message}`);
    }
  };

  // Bob sends a message
  const sendBobMessage = async () => {
    try {
      if (!bobInput.trim()) return;

      const envelope = await bobManager.encryptMessage(groupId, bobInput);
      addLog(`📤 Bob sent encrypted message`);

      // Add to Bob's view
      setBobMessages((prev) => [...prev, { from: 'Bob', text: bobInput, encrypted: false }]);

      // Alice and Charlie decrypt
      const aliceDecrypted = await aliceManager.decryptMessage(envelope);
      setAliceMessages((prev) => [...prev, { from: 'Bob', text: aliceDecrypted, encrypted: true }]);

      const charlieDecrypted = await charlieManager.decryptMessage(envelope);
      setCharlieMessages((prev) => [...prev, { from: 'Bob', text: charlieDecrypted, encrypted: true }]);

      addLog(`✅ Message delivered to Alice and Charlie`);
      setBobInput('');
    } catch (err) {
      console.error('Send error:', err);
      setError(`Send failed: ${err.message}`);
      addLog(`❌ Send failed: ${err.message}`);
    }
  };

  // Charlie sends a message
  const sendCharlieMessage = async () => {
    try {
      if (!charlieInput.trim()) return;

      const envelope = await charlieManager.encryptMessage(groupId, charlieInput);
      addLog(`📤 Charlie sent encrypted message`);

      // Add to Charlie's view
      setCharlieMessages((prev) => [...prev, { from: 'Charlie', text: charlieInput, encrypted: false }]);

      // Alice and Bob decrypt
      const aliceDecrypted = await aliceManager.decryptMessage(envelope);
      setAliceMessages((prev) => [...prev, { from: 'Charlie', text: aliceDecrypted, encrypted: true }]);

      const bobDecrypted = await bobManager.decryptMessage(envelope);
      setBobMessages((prev) => [...prev, { from: 'Charlie', text: bobDecrypted, encrypted: true }]);

      addLog(`✅ Message delivered to Alice and Bob`);
      setCharlieInput('');
    } catch (err) {
      console.error('Send error:', err);
      setError(`Send failed: ${err.message}`);
      addLog(`❌ Send failed: ${err.message}`);
    }
  };

  // Perform key rotation
  const rotateKeys = async () => {
    try {
      addLog('🔄 Performing key rotation...');

      const commit = await aliceManager.updateKey(groupId);
      await bobManager.processCommit(groupId, commit);
      await charlieManager.processCommit(groupId, commit);

      addLog('✅ Key rotation successful');
      setStatus('Keys rotated');
    } catch (err) {
      console.error('Key rotation error:', err);
      setError(`Key rotation failed: ${err.message}`);
      addLog(`❌ Key rotation failed: ${err.message}`);
    }
  };

  return (
    <ThemeProvider>
      <Container maxWidth="xl" sx={{ py: 3 }}>
        <Typography variant="h4" gutterBottom>
          🔐 MLS (Message Layer Security) Demo
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          RFC 9420 - End-to-End Encrypted Group Messaging
        </Typography>

        {/* Status Bar */}
        <Paper sx={{ p: 2, mb: 3, bgcolor: 'action.hover' }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Typography variant="subtitle2">Status:</Typography>
            <Chip label={status} color={status.includes('ready') ? 'success' : 'default'} size="small" />
            <Box sx={{ flexGrow: 1 }} />
            <Button
              variant="contained"
              onClick={initializeManagers}
              disabled={!!aliceManager}
              size="small"
            >
              1. Initialize
            </Button>
            <Button
              variant="contained"
              onClick={createGroup}
              disabled={!aliceManager || status.includes('ready')}
              size="small"
            >
              2. Create Group
            </Button>
            <Button
              variant="outlined"
              onClick={rotateKeys}
              disabled={!status.includes('ready')}
              size="small"
            >
              Rotate Keys
            </Button>
          </Stack>
        </Paper>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Chat Windows */}
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 2, mb: 3 }}>
          {/* Alice */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              👩 Alice
            </Typography>
            <Box sx={{ height: 300, overflowY: 'auto', mb: 2, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
              {aliceMessages.map((msg, idx) => (
                <Box key={idx} sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && '🔒'}
                  </Typography>
                  <Typography variant="body2">{msg.text}</Typography>
                </Box>
              ))}
            </Box>
            <Stack direction="row" spacing={1}>
              <TextField
                fullWidth
                size="small"
                value={aliceInput}
                onChange={(e) => setAliceInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendAliceMessage()}
                placeholder="Type message..."
                disabled={!status.includes('ready')}
              />
              <Button onClick={sendAliceMessage} disabled={!status.includes('ready')}>
                Send
              </Button>
            </Stack>
          </Paper>

          {/* Bob */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              👨 Bob
            </Typography>
            <Box sx={{ height: 300, overflowY: 'auto', mb: 2, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
              {bobMessages.map((msg, idx) => (
                <Box key={idx} sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && '🔒'}
                  </Typography>
                  <Typography variant="body2">{msg.text}</Typography>
                </Box>
              ))}
            </Box>
            <Stack direction="row" spacing={1}>
              <TextField
                fullWidth
                size="small"
                value={bobInput}
                onChange={(e) => setBobInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendBobMessage()}
                placeholder="Type message..."
                disabled={!status.includes('ready')}
              />
              <Button onClick={sendBobMessage} disabled={!status.includes('ready')}>
                Send
              </Button>
            </Stack>
          </Paper>

          {/* Charlie */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              🧑 Charlie
            </Typography>
            <Box sx={{ height: 300, overflowY: 'auto', mb: 2, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
              {charlieMessages.map((msg, idx) => (
                <Box key={idx} sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && '🔒'}
                  </Typography>
                  <Typography variant="body2">{msg.text}</Typography>
                </Box>
              ))}
            </Box>
            <Stack direction="row" spacing={1}>
              <TextField
                fullWidth
                size="small"
                value={charlieInput}
                onChange={(e) => setCharlieInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendCharlieMessage()}
                placeholder="Type message..."
                disabled={!status.includes('ready')}
              />
              <Button onClick={sendCharlieMessage} disabled={!status.includes('ready')}>
                Send
              </Button>
            </Stack>
          </Paper>
        </Box>

        {/* Logs */}
        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            📋 Logs
          </Typography>
          <Box sx={{ height: 200, overflowY: 'auto', p: 1, bgcolor: 'background.default', fontFamily: 'monospace', fontSize: '0.875rem' }}>
            {logs.map((log, idx) => (
              <div key={idx}>{log}</div>
            ))}
          </Box>
        </Paper>

        {/* Key Info */}
        {keyInfo && (
          <Paper sx={{ p: 2, mt: 2, bgcolor: 'success.main', color: 'success.contrastText' }}>
            <Typography variant="subtitle2" gutterBottom>
              🔑 Encryption Key Information
            </Typography>
            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
              Group: {keyInfo.groupId}<br />
              Epoch: {keyInfo.epoch}<br />
              Key ID: {keyInfo.keyId}<br />
              Algorithm: {keyInfo.keyAlgorithm}<br />
              Members: {keyInfo.members.join(', ')}
            </Typography>
          </Paper>
        )}

        {/* Info Box */}
        <Paper sx={{ p: 2, mt: 2, bgcolor: 'info.main', color: 'info.contrastText' }}>
          <Typography variant="subtitle2" gutterBottom>
            ℹ️ How it works:
          </Typography>
          <Typography variant="body2">
            1. Click "Initialize" to create MLS clients for Alice, Bob, and Charlie<br />
            2. Click "Create Group" to set up an encrypted group with shared AES-256-GCM key<br />
            3. Send messages - they're encrypted with the shared key and decrypted on each peer<br />
            4. Use "Rotate Keys" to demonstrate forward secrecy (generates new epoch and key)<br />
            5. 🔒 = Message was encrypted during transmission and actually decrypted
          </Typography>
        </Paper>
      </Container>
    </ThemeProvider>
  );
};

export const Interactive = () => <MLSDemoApp />;
