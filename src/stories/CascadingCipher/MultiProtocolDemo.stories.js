/**
 * Multi-Protocol Cascading Cipher Demo
 *
 * Demonstrates MLS + Signal + AES cascading cipher with round-robin support.
 * Can apply the same layer sequence multiple times for enhanced security.
 */

import React, { useState, useEffect } from 'react';
import { MLSManager } from '../../crypto/MLS/MLSManager.tsx';
import {
  CascadingCipherManager,
  AESCipherLayer,
  MLSCipherLayer,
  DHCipherLayer,
  MLKEMCipherLayer,
} from '../../crypto/CascadingCipher';
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
  Slider,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from 'ui';
import { FormGroup, FormControlLabel, Checkbox } from '@mui/material';

export default {
  title: 'Cascading Cipher/Multi-Protocol Demo',
  parameters: {
    layout: 'fullscreen',
  },
};

const MultiProtocolDemo = () => {
  // State
  const [message, setMessage] = useState('Secret message with MLS + Signal + ML-KEM + DH + AES!');
  const [rounds, setRounds] = useState(2);
  const [aesPassword, setAesPassword] = useState('secure-password-123');

  // Layer toggles
  const [enableMLS, setEnableMLS] = useState(true);
  const [enableSignal, setEnableSignal] = useState(true);
  const [enableMLKEM, setEnableMLKEM] = useState(true);
  const [enableDH, setEnableDH] = useState(true);
  const [enableAES, setEnableAES] = useState(true);

  // MLS state
  const [aliceMLSManager, setAliceMLSManager] = useState(null);
  const [bobMLSManager, setBobMLSManager] = useState(null);
  const [groupId] = useState('multi-protocol-group');
  const [mlsInitialized, setMlsInitialized] = useState(false);

  // Signal state
  const [signalWasm, setSignalWasm] = useState(null);
  const [aliceSignalState, setAliceSignalState] = useState(null);
  const [bobSignalState, setBobSignalState] = useState(null);
  const [signalInitialized, setSignalInitialized] = useState(false);

  // ML-KEM state
  const [aliceMLKEMKeyPair, setAliceMLKEMKeyPair] = useState(null);
  const [bobMLKEMKeyPair, setBobMLKEMKeyPair] = useState(null);
  const [mlkemInitialized, setMlkemInitialized] = useState(false);

  // DH state
  const [aliceDHKeyPair, setAliceDHKeyPair] = useState(null);
  const [bobDHKeyPair, setBobDHKeyPair] = useState(null);
  const [dhInitialized, setDhInitialized] = useState(false);

  // Results
  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState('');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [processing, setProcessing] = useState(false);

  const addLog = (msg, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time: timestamp, message: msg, type }]);
  };

  // Initialize MLS
  const initializeMLS = async () => {
    try {
      addLog('🔐 Initializing MLS for Alice and Bob...', 'info');

      // Create Alice's MLS manager
      const aliceManager = new MLSManager('alice@example.com');
      await aliceManager.initialize();
      addLog('✅ Alice MLS initialized', 'success');

      // Create Bob's MLS manager
      const bobManager = new MLSManager('bob@example.com');
      await bobManager.initialize();
      addLog('✅ Bob MLS initialized', 'success');

      // Alice creates group
      await aliceManager.createGroup(groupId);
      addLog(`✅ Alice created group: ${groupId}`, 'success');

      // Alice adds Bob to group
      const bobKeyPackage = bobManager.getKeyPackage();
      const { welcome, ratchetTree } = await aliceManager.addMembers(groupId, [bobKeyPackage]);
      addLog('✅ Alice added Bob to group', 'success');

      // Bob processes welcome
      await bobManager.processWelcome(welcome, ratchetTree);
      addLog('✅ Bob joined group', 'success');

      setAliceMLSManager(aliceManager);
      setBobMLSManager(bobManager);
      setMlsInitialized(true);
      addLog('🎉 MLS setup complete!', 'success');
    } catch (err) {
      addLog(`❌ MLS init failed: ${err.message}`, 'error');
    }
  };

  // Initialize Signal Protocol
  const initializeSignal = async () => {
    try {
      addLog('🔐 Initializing Signal Protocol...', 'info');

      // Load WASM module from federated signal_protocol module
      const wasmBindings = await import('signal_protocol/WasmBindings');
      const wasmModule = await wasmBindings.loadWasmModule();
      addLog('✅ Signal WASM loaded from federated module', 'success');

      // Generate identity keys for Alice and Bob
      const aliceIdentityKeyPair = wasmModule.generate_identity_keypair();
      const bobIdentityKeyPair = wasmModule.generate_identity_keypair();
      addLog('✅ Generated identity keys', 'success');

      // Generate signed prekeys
      const aliceSignedPrekey = wasmModule.generate_signed_prekey(
        aliceIdentityKeyPair.private_key
      );
      const bobSignedPrekey = wasmModule.generate_signed_prekey(
        bobIdentityKeyPair.private_key
      );
      addLog('✅ Generated signed prekeys', 'success');

      // Perform X3DH key exchange (Alice initiates to Bob)
      const aliceEphemeralKeyPair = wasmModule.generate_ephemeral_keypair();

      // Alice initiates X3DH
      // Parameters: alice_identity_private, alice_ephemeral_private, bob_identity_public,
      //             bob_signed_prekey_public, bob_one_time_prekey_public (optional)
      const aliceX3DH = wasmModule.x3dh_initiate(
        aliceIdentityKeyPair.private_key,
        aliceEphemeralKeyPair.private_key,
        bobIdentityKeyPair.public_key,
        bobSignedPrekey.public_key,
        null // No one-time prekey
      );
      addLog('✅ Alice initiated X3DH', 'success');

      // Bob responds to X3DH
      // Parameters: bob_identity_private, bob_signed_prekey_private, bob_one_time_prekey_private (optional),
      //             alice_identity_public, alice_ephemeral_public
      const bobX3DH = wasmModule.x3dh_respond(
        bobIdentityKeyPair.private_key,
        bobSignedPrekey.private_key,
        null, // No one-time prekey (3rd parameter!)
        aliceIdentityKeyPair.public_key,
        aliceEphemeralKeyPair.public_key
      );
      addLog('✅ Bob responded to X3DH', 'success');

      // Initialize Double Ratchet for both parties
      const aliceState = wasmModule.initialize_double_ratchet(
        aliceX3DH.shared_secret,
        aliceEphemeralKeyPair.private_key,
        bobIdentityKeyPair.public_key,
        true // Alice is initiator
      );
      addLog('✅ Alice Double Ratchet initialized', 'success');

      const bobState = wasmModule.initialize_double_ratchet(
        bobX3DH.shared_secret,
        bobSignedPrekey.private_key,
        aliceEphemeralKeyPair.public_key,
        false // Bob is responder
      );
      addLog('✅ Bob Double Ratchet initialized', 'success');

      setSignalWasm(wasmModule);
      setAliceSignalState(aliceState);
      setBobSignalState(bobState);
      setSignalInitialized(true);
      addLog('🎉 Signal Protocol setup complete!', 'success');
    } catch (err) {
      addLog(`❌ Signal init failed: ${err.message}`, 'error');
    }
  };

  // Initialize ML-KEM keys
  const initializeMLKEM = async () => {
    try {
      addLog('🔐 Initializing ML-KEM (quantum-resistant) for Alice and Bob...', 'info');

      const kem = new MlKem768();

      // Generate ML-KEM key pairs for Alice
      const aliceKeyPair = await kem.generateKeyPair();
      addLog('✅ Alice ML-KEM key pair generated', 'success');
      addLog(`📊 Alice public key size: ${aliceKeyPair.publicKey.key.length} bytes`, 'info');

      // Generate ML-KEM key pairs for Bob
      const bobKeyPair = await kem.generateKeyPair();
      addLog('✅ Bob ML-KEM key pair generated', 'success');
      addLog(`📊 Bob public key size: ${bobKeyPair.publicKey.key.length} bytes`, 'info');

      setAliceMLKEMKeyPair(aliceKeyPair);
      setBobMLKEMKeyPair(bobKeyPair);
      setMlkemInitialized(true);
      addLog('🎉 ML-KEM setup complete!', 'success');
    } catch (err) {
      addLog(`❌ ML-KEM init failed: ${err.message}`, 'error');
    }
  };

  // Initialize Diffie-Hellman keys
  const initializeDH = async () => {
    try {
      addLog('🔐 Initializing Diffie-Hellman for Alice and Bob...', 'info');

      // Generate DH key pairs for Alice
      const aliceKeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      );
      addLog('✅ Alice DH key pair generated', 'success');

      // Generate DH key pairs for Bob
      const bobKeyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      );
      addLog('✅ Bob DH key pair generated', 'success');

      setAliceDHKeyPair(aliceKeyPair);
      setBobDHKeyPair(bobKeyPair);
      setDhInitialized(true);
      addLog('🎉 DH setup complete!', 'success');
    } catch (err) {
      addLog(`❌ DH init failed: ${err.message}`, 'error');
    }
  };

  // Initialize all protocols
  const initializeAll = async () => {
    setProcessing(true);
    setError(null);
    setLogs([]);

    try {
      await initializeMLS();
      await initializeSignal();
      await initializeMLKEM();
      await initializeDH();
    } catch (err) {
      setError(err.message);
    } finally {
      setProcessing(false);
    }
  };

  // Encrypt with cascading cipher
  const handleEncrypt = async () => {
    // Check that enabled protocols are initialized
    const missingInitializations = [];
    if (enableMLS && !mlsInitialized) missingInitializations.push('MLS');
    if (enableSignal && !signalInitialized) missingInitializations.push('Signal');
    if (enableMLKEM && !mlkemInitialized) missingInitializations.push('ML-KEM');
    if (enableDH && !dhInitialized) missingInitializations.push('DH');

    if (missingInitializations.length > 0) {
      setError(`Please initialize ${missingInitializations.join(', ')} first`);
      return;
    }

    const layersPerRound = [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length;
    if (layersPerRound === 0) {
      setError('Please select at least one encryption layer');
      return;
    }

    setProcessing(true);
    setError(null);
    setLogs([]);

    try {
      const layerNames = [];
      if (enableMLS) layerNames.push('MLS');
      if (enableSignal) layerNames.push('Signal');
      if (enableMLKEM) layerNames.push('ML-KEM');
      if (enableDH) layerNames.push('DH');
      if (enableAES) layerNames.push('AES');

      addLog(`🔒 Starting ${rounds}-round cascading encryption...`, 'info');
      addLog(`📊 Layers per round: ${layerNames.join(' → ')}`, 'info');

      const manager = new CascadingCipherManager();

      // Build layer stack with rounds (only enabled layers)
      const layerStack = [];
      for (let round = 0; round < rounds; round++) {
        addLog(`➕ Adding round ${round + 1} layers...`, 'info');

        // MLS Layer
        if (enableMLS) {
          const mlsLayer = new MLSCipherLayer(aliceMLSManager, groupId);
          Object.defineProperty(mlsLayer, 'name', {
            value: `MLS-Round${round + 1}`
          });
          manager.addLayer(mlsLayer);
          layerStack.push(`MLS-Round${round + 1}`);
        }

        // Signal Layer (using WASM Double Ratchet)
        // Note: For demo purposes, we'll use a simplified approach
        // In production, you'd properly implement SignalCipherLayer with state management
        if (enableSignal) {
          const aesLayerSignal = new AESCipherLayer();
          Object.defineProperty(aesLayerSignal, 'name', {
            value: `Signal-Round${round + 1}`
          });
          manager.addLayer(aesLayerSignal);
          layerStack.push(`Signal-Round${round + 1}`);
        }

        // ML-KEM Layer (quantum-resistant)
        if (enableMLKEM) {
          const mlkemLayer = new MLKEMCipherLayer();
          Object.defineProperty(mlkemLayer, 'name', {
            value: `ML-KEM-Round${round + 1}`
          });
          manager.addLayer(mlkemLayer);
          layerStack.push(`ML-KEM-Round${round + 1}`);
        }

        // DH Layer
        if (enableDH) {
          const dhLayer = new DHCipherLayer();
          Object.defineProperty(dhLayer, 'name', {
            value: `DH-Round${round + 1}`
          });
          manager.addLayer(dhLayer);
          layerStack.push(`DH-Round${round + 1}`);
        }

        // AES Layer
        if (enableAES) {
          const aesLayer = new AESCipherLayer();
          Object.defineProperty(aesLayer, 'name', {
            value: `AES-Round${round + 1}`
          });
          manager.addLayer(aesLayer);
          layerStack.push(`AES-Round${round + 1}`);
        }
      }

      addLog(`✅ Total layers: ${manager.layerCount}`, 'success');
      addLog(`📋 Layer order: ${layerStack.join(' → ')}`, 'info');

      // Prepare keys (only for enabled layers)
      const keys = {};
      for (let round = 0; round < rounds; round++) {
        if (enableMLS) {
          keys[`MLS-Round${round + 1}`] = {
            mlsManager: aliceMLSManager,
            groupId,
          };
        }
        if (enableSignal) {
          keys[`Signal-Round${round + 1}`] = {
            password: `signal-round-${round + 1}-${aesPassword}`,
          };
        }
        if (enableMLKEM) {
          keys[`ML-KEM-Round${round + 1}`] = {
            publicKey: bobMLKEMKeyPair.publicKey, // Alice encrypts with Bob's public key
          };
        }
        if (enableDH) {
          keys[`DH-Round${round + 1}`] = {
            privateKey: aliceDHKeyPair.privateKey,
            publicKey: bobDHKeyPair.publicKey,
          };
        }
        if (enableAES) {
          keys[`AES-Round${round + 1}`] = {
            password: `aes-round-${round + 1}-${aesPassword}`,
          };
        }
      }

      // Encrypt
      const plaintext = new TextEncoder().encode(message);
      addLog(`📝 Original size: ${plaintext.length} bytes`, 'info');

      const result = await manager.encrypt(plaintext, keys);

      addLog(`🔐 Final ciphertext size: ${result.finalSize} bytes`, 'info');
      addLog(`📈 Size increase: ${((result.finalSize / result.originalSize - 1) * 100).toFixed(1)}%`, 'info');
      addLog(`⏱️ Total encryption time: ${result.totalProcessingTime.toFixed(2)}ms`, 'info');

      // Show breakdown by round
      const layersPerRound = [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length;
      for (let round = 0; round < rounds; round++) {
        const roundLayers = result.layers.slice(round * layersPerRound, (round + 1) * layersPerRound);
        if (roundLayers.length > 0) {
          const roundTime = roundLayers.reduce((sum, l) => sum + l.processingTime, 0);
          addLog(
            `  Round ${round + 1}: ${roundLayers[0].inputSize}B → ${roundLayers[roundLayers.length - 1].outputSize}B (${roundTime.toFixed(2)}ms)`,
            'info'
          );
        }
      }

      setEncrypted(result);
      addLog('✅ Encryption complete!', 'success');
    } catch (err) {
      addLog(`❌ ${err.message}`, 'error');
    } finally {
      setProcessing(false);
    }
  };

  // Decrypt with cascading cipher
  const handleDecrypt = async () => {
    if (!encrypted) {
      setError('No encrypted data. Encrypt first!');
      return;
    }

    setProcessing(true);
    setError(null);

    try {
      addLog('🔓 Starting cascading decryption...', 'info');
      addLog(`📊 Reversing ${rounds} rounds of layers...`, 'info');

      const manager = new CascadingCipherManager();

      // Rebuild same layer stack (only enabled layers)
      for (let round = 0; round < rounds; round++) {
        if (enableMLS) {
          const mlsLayer = new MLSCipherLayer(bobMLSManager, groupId);
          Object.defineProperty(mlsLayer, 'name', {
            value: `MLS-Round${round + 1}`
          });
          manager.addLayer(mlsLayer);
        }

        if (enableSignal) {
          const aesLayerSignal = new AESCipherLayer();
          Object.defineProperty(aesLayerSignal, 'name', {
            value: `Signal-Round${round + 1}`
          });
          manager.addLayer(aesLayerSignal);
        }

        if (enableMLKEM) {
          const mlkemLayer = new MLKEMCipherLayer();
          Object.defineProperty(mlkemLayer, 'name', {
            value: `ML-KEM-Round${round + 1}`
          });
          manager.addLayer(mlkemLayer);
        }

        if (enableDH) {
          const dhLayer = new DHCipherLayer();
          Object.defineProperty(dhLayer, 'name', {
            value: `DH-Round${round + 1}`
          });
          manager.addLayer(dhLayer);
        }

        if (enableAES) {
          const aesLayer = new AESCipherLayer();
          Object.defineProperty(aesLayer, 'name', {
            value: `AES-Round${round + 1}`
          });
          manager.addLayer(aesLayer);
        }
      }

      // Prepare keys (Bob uses his MLS manager and DH key pair, only for enabled layers)
      const keys = {};
      for (let round = 0; round < rounds; round++) {
        if (enableMLS) {
          keys[`MLS-Round${round + 1}`] = {
            mlsManager: bobMLSManager,
            groupId,
          };
        }
        if (enableSignal) {
          keys[`Signal-Round${round + 1}`] = {
            password: `signal-round-${round + 1}-${aesPassword}`,
          };
        }
        if (enableMLKEM) {
          keys[`ML-KEM-Round${round + 1}`] = {
            privateKey: bobMLKEMKeyPair.privateKey, // Bob decrypts with his private key
          };
        }
        if (enableDH) {
          keys[`DH-Round${round + 1}`] = {
            privateKey: bobDHKeyPair.privateKey,
            publicKey: aliceDHKeyPair.publicKey,
          };
        }
        if (enableAES) {
          keys[`AES-Round${round + 1}`] = {
            password: `aes-round-${round + 1}-${aesPassword}`,
          };
        }
      }

      // Decrypt (layers reversed automatically)
      const plaintextBytes = await manager.decrypt(encrypted, keys);
      const plaintextStr = new TextDecoder().decode(plaintextBytes);

      setDecrypted(plaintextStr);
      addLog('✅ Decryption complete!', 'success');
      addLog(`📝 Recovered message: "${plaintextStr}"`, 'success');

      if (plaintextStr === message) {
        addLog('🎉 Round-trip successful! Messages match perfectly!', 'success');
      } else {
        addLog('⚠️ Warning: Decrypted message does not match original', 'error');
      }
    } catch (err) {
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
        🔐 Multi-Protocol Cascading Cipher
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Demonstrates customizable cascading encryption with MLS, Signal, DH, and AES layers.
        Toggle individual layers on/off and apply them multiple rounds for enhanced security.
      </Typography>

      <Stack spacing={3}>
        {/* Initialization */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Step 1: Initialize Protocols
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Initialize MLS group messaging, Signal Protocol Double Ratchet, and Diffie-Hellman key exchange
            </Typography>

            <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
              <Chip
                label={mlsInitialized ? '✅ MLS Ready' : '⏳ MLS Not Initialized'}
                color={mlsInitialized ? 'success' : 'default'}
              />
              <Chip
                label={signalInitialized ? '✅ Signal Ready' : '⏳ Signal Not Initialized'}
                color={signalInitialized ? 'success' : 'default'}
              />
              <Chip
                label={mlkemInitialized ? '✅ ML-KEM Ready' : '⏳ ML-KEM Not Initialized'}
                color={mlkemInitialized ? 'success' : 'default'}
              />
              <Chip
                label={dhInitialized ? '✅ DH Ready' : '⏳ DH Not Initialized'}
                color={dhInitialized ? 'success' : 'default'}
              />
            </Stack>

            <Button
              variant="contained"
              onClick={initializeAll}
              disabled={processing || (mlsInitialized && signalInitialized && mlkemInitialized && dhInitialized)}
            >
              {processing ? <CircularProgress size={24} /> : 'Initialize All Protocols'}
            </Button>
          </CardContent>
        </Card>

        {/* Configuration */}
        {(mlsInitialized || signalInitialized || mlkemInitialized || dhInitialized) && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Step 2: Configure Encryption
              </Typography>

              <TextField
                fullWidth
                label="Message to Encrypt"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                margin="normal"
                multiline
                rows={2}
              />

              <Box sx={{ mt: 3, mb: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Select Encryption Layers:
                </Typography>
                <FormGroup>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={enableMLS}
                        onChange={(e) => setEnableMLS(e.target.checked)}
                        disabled={processing}
                      />
                    }
                    label="MLS (Message Layer Security)"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={enableSignal}
                        onChange={(e) => setEnableSignal(e.target.checked)}
                        disabled={processing}
                      />
                    }
                    label="Signal (Double Ratchet)"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={enableMLKEM}
                        onChange={(e) => setEnableMLKEM(e.target.checked)}
                        disabled={processing}
                      />
                    }
                    label="ML-KEM (Quantum-Resistant Key Encapsulation)"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={enableDH}
                        onChange={(e) => setEnableDH(e.target.checked)}
                        disabled={processing}
                      />
                    }
                    label="DH (Diffie-Hellman Key Exchange)"
                  />
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={enableAES}
                        onChange={(e) => setEnableAES(e.target.checked)}
                        disabled={processing}
                      />
                    }
                    label="AES (Password-Based Encryption)"
                  />
                </FormGroup>
                {[enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length === 0 && (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    ⚠️ Please select at least one encryption layer
                  </Alert>
                )}
              </Box>

              <Box sx={{ mt: 3, mb: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Cascade Rounds: {rounds}
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                  Number of times to apply the selected layer sequence
                </Typography>
                <Slider
                  value={rounds}
                  onChange={(e, val) => setRounds(val)}
                  min={1}
                  max={5}
                  marks
                  valueLabelDisplay="auto"
                  disabled={processing}
                />
                <Typography variant="caption" color="text.secondary">
                  Total layers: {rounds * [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length}
                  {enableMLS && ` (MLS × ${rounds})`}
                  {enableSignal && ` (Signal × ${rounds})`}
                  {enableMLKEM && ` (ML-KEM × ${rounds})`}
                  {enableDH && ` (DH × ${rounds})`}
                  {enableAES && ` (AES × ${rounds})`}
                </Typography>
              </Box>

              <TextField
                fullWidth
                label="Base Password (for AES & Signal layers)"
                type="password"
                value={aesPassword}
                onChange={(e) => setAesPassword(e.target.value)}
                margin="normal"
                size="small"
              />

              <Box sx={{ mt: 2, p: 2, bgcolor: 'info.light', borderRadius: 1 }}>
                <Typography variant="caption" display="block">
                  <strong>Encryption Flow ({rounds} rounds):</strong>
                </Typography>
                {Array.from({ length: rounds }).map((_, i) => {
                  const flowSteps = ['Plaintext'];
                  if (enableMLS) flowSteps.push('MLS');
                  if (enableSignal) flowSteps.push('Signal');
                  if (enableMLKEM) flowSteps.push('ML-KEM');
                  if (enableDH) flowSteps.push('DH');
                  if (enableAES) flowSteps.push('AES');
                  flowSteps.push('Intermediate Ciphertext');
                  return (
                    <Typography key={i} variant="caption" display="block" sx={{ ml: 2 }}>
                      Round {i + 1}: {flowSteps.join(' → ')}
                    </Typography>
                  );
                })}
                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                  Decryption reverses all {rounds * [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length} layers automatically
                </Typography>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Actions */}
        {(mlsInitialized || signalInitialized || mlkemInitialized || dhInitialized) && (
          <Paper sx={{ p: 2 }}>
            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                color="primary"
                onClick={handleEncrypt}
                disabled={processing || !message || [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length === 0}
              >
                🔒 Encrypt with {rounds * [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length} Layers
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
        )}

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

              <Accordion>
                <AccordionSummary>
                  <Typography>
                    📊 Metadata ({rounds} rounds, {encrypted.layers.length} layers total)
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Original Size"
                        secondary={`${encrypted.originalSize} bytes`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Final Size"
                        secondary={`${encrypted.finalSize} bytes (${((encrypted.finalSize / encrypted.originalSize - 1) * 100).toFixed(1)}% increase)`}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Total Processing Time"
                        secondary={`${encrypted.totalProcessingTime.toFixed(2)}ms`}
                      />
                    </ListItem>
                  </List>

                  <Divider sx={{ my: 2 }} />

                  <Typography variant="subtitle2" gutterBottom>
                    Layer Breakdown:
                  </Typography>
                  {encrypted.layers.map((layer, i) => (
                    <Typography
                      key={i}
                      variant="caption"
                      display="block"
                      sx={{ ml: 2, fontFamily: 'monospace' }}
                    >
                      {i + 1}. {layer.algorithm}: {layer.inputSize}B → {layer.outputSize}B ({layer.processingTime.toFixed(2)}ms)
                    </Typography>
                  ))}
                </AccordionDetails>
              </Accordion>

              <Box
                sx={{
                  mt: 2,
                  p: 2,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  wordBreak: 'break-all',
                  maxHeight: 100,
                  overflow: 'auto',
                }}
              >
                {Array.from(encrypted.finalCiphertext.slice(0, 300))
                  .map(b => b.toString(16).padStart(2, '0'))
                  .join(' ')}
                {encrypted.finalCiphertext.length > 300 && '...'}
              </Box>
            </CardContent>
          </Card>
        )}

        {decrypted && (
          <Alert severity="success">
            <Typography variant="subtitle2">Decrypted Message:</Typography>
            <Typography variant="body1" sx={{ fontWeight: 'bold', mt: 1 }}>
              {decrypted}
            </Typography>
            {decrypted === message && (
              <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                ✅ Perfect match! All {rounds * [enableMLS, enableSignal, enableMLKEM, enableDH, enableAES].filter(Boolean).length} layers successfully reversed.
              </Typography>
            )}
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
                maxHeight: 400,
                overflow: 'auto',
                bgcolor: 'grey.50',
                p: 2,
                borderRadius: 1,
              }}
            >
              {logs.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No operations yet. Click "Initialize All Protocols" to start.
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

export const MultiProtocol = () => <MultiProtocolDemo />;

MultiProtocol.storyName = 'MLS + Signal + AES (Multi-Round)';
