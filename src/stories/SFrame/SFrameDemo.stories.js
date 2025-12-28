/**
 * SFrame (Secure Frame) Demo
 * Interactive demonstration of real-time media frame encryption
 */

import React, { useState } from "react";
import { SFrameManager } from "../../crypto/SFrame/SFrameManager.tsx";
import {
  ThemeProvider,
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Stack,
  Chip,
  Alert,
  TextField,
} from "ui";

export default {
  title: "SFrame/SFrameDemo",
  parameters: {
    layout: "fullscreen",
  },
};

const SFrameDemoApp = () => {
  const [aliceManager, setAliceManager] = useState(null);
  const [bobManager, setBobManager] = useState(null);

  const [testMessage, setTestMessage] = useState(
    "Hello from encrypted video frame! 🎥",
  );
  const [encryptedData, setEncryptedData] = useState(null);
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [currentSharedSecret, setCurrentSharedSecret] = useState(null); // Track the shared secret

  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState("Not initialized");
  const [stats, setStats] = useState(null);

  const addLog = (message) => {
    setLogs((prev) => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] ${message}`,
    ]);
  };

  // Initialize SFrame managers
  const initializeManagers = async () => {
    try {
      setStatus("Initializing...");
      addLog("🎥 Initializing SFrame managers...");

      // Create managers for Alice (sender) and Bob (receiver)
      const alice = new SFrameManager();
      const bob = new SFrameManager();

      // Initialize them
      await alice.initialize();
      addLog("✅ Alice (sender) initialized");

      await bob.initialize();
      addLog("✅ Bob (receiver) initialized");

      setAliceManager(alice);
      setBobManager(bob);

      // Update stats
      setStats({
        alice: alice.getStats(),
        bob: bob.getStats(),
      });

      setStatus("Initialized");
      addLog("✅ All managers initialized successfully");
    } catch (err) {
      addLog(`❌ Initialization failed: ${err.message}`);
    }
  };

  // Simulate key exchange (in real app, this would come from MLS)
  const exchangeKeys = async () => {
    try {
      if (!aliceManager || !bobManager) {
        throw new Error("Managers not initialized");
      }

      setStatus("Exchanging keys...");
      addLog("🔑 Simulating key exchange...");

      // In a real application, this would be an MLS shared secret
      // For demo, we'll generate a shared secret
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));

      // Store the shared secret
      setCurrentSharedSecret(sharedSecret);

      // Both Alice and Bob derive SFrame keys from the same MLS secret
      await aliceManager.deriveKeyFromMLSSecret(
        sharedSecret.buffer,
        1,
        "Demo_SFrame_Key",
      );
      await bobManager.deriveKeyFromMLSSecret(
        sharedSecret.buffer,
        1,
        "Demo_SFrame_Key",
      );

      // Set as active key
      aliceManager.setActiveKey(1);
      bobManager.setActiveKey(1);

      // Clear any old encrypted data
      setEncryptedData(null);
      setDecryptedMessage("");

      addLog("✅ Keys exchanged and set as active");
      addLog(
        `   Shared Secret: ${Array.from(sharedSecret)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
          .substring(0, 32)}...`,
      );

      // Update stats
      setStats({
        alice: aliceManager.getStats(),
        bob: bobManager.getStats(),
      });

      setStatus("Ready for encrypted streaming");
    } catch (err) {
      addLog(`❌ Key exchange failed: ${err.message}`);
    }
  };

  // Capture camera frames
  const startCameraEncryption = async () => {
    try {
      if (!aliceManager) {
        throw new Error("Alice not initialized");
      }

      addLog("📷 Starting camera capture...");

      // Get camera stream
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: false,
      });

      // Create video element to capture frames
      const video = document.createElement("video");
      video.srcObject = stream;
      video.play();

      addLog("✅ Camera started");

      // Create canvas for frame capture
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");

      // Wait for video to be ready
      await new Promise((resolve) => {
        video.onloadedmetadata = () => {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          resolve();
        };
      });

      addLog("🎥 Capturing and encrypting frame...");

      // Capture one frame
      ctx.drawImage(video, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const frameData = imageData.data.buffer;

      addLog(`📤 Frame captured (${frameData.byteLength} bytes)`);

      // Encrypt the frame
      const encrypted = await aliceManager.encryptFrame(frameData);

      setEncryptedData(encrypted);
      addLog(`✅ Frame encrypted (${encrypted.length} bytes)`);
      addLog(
        `   Original: ${frameData.byteLength} bytes → Encrypted: ${encrypted.length} bytes`,
      );
      addLog(
        `   Overhead: ${encrypted.length - frameData.byteLength} bytes (~${(((encrypted.length - frameData.byteLength) / frameData.byteLength) * 100).toFixed(2)}%)`,
      );

      // Stop camera
      stream.getTracks().forEach((track) => track.stop());

      // Update stats
      setStats({
        alice: aliceManager.getStats(),
        bob: bobManager?.getStats(),
      });
    } catch (err) {
      addLog(`❌ Encryption failed: ${err.message}`);
    }
  };

  // Simulate frame encryption with text
  const encryptFrame = async () => {
    try {
      if (!aliceManager) {
        throw new Error("Alice not initialized");
      }

      addLog(`📤 Alice encrypting frame: "${testMessage}"`);

      // Convert message to ArrayBuffer (simulating video frame data)
      const frameData = new TextEncoder().encode(testMessage);

      // Encrypt the "frame"
      const encrypted = await aliceManager.encryptFrame(frameData.buffer);

      setEncryptedData(encrypted);
      addLog(`✅ Frame encrypted (${encrypted.length} bytes)`);
      addLog(
        `   Original: ${frameData.length} bytes → Encrypted: ${encrypted.length} bytes`,
      );
      addLog(`   Overhead: ${encrypted.length - frameData.length} bytes`);

      // Update stats
      setStats({
        alice: aliceManager.getStats(),
        bob: bobManager?.getStats(),
      });
    } catch (err) {
      addLog(`❌ Encryption failed: ${err.message}`);
    }
  };

  // Simulate frame decryption
  const decryptFrame = async () => {
    try {
      if (!bobManager || !encryptedData) {
        throw new Error("Bob not initialized or no encrypted data");
      }

      if (!currentSharedSecret) {
        throw new Error('Keys not exchanged yet! Click "Exchange Keys" first.');
      }

      addLog("📥 Bob decrypting frame...");

      // Decrypt the "frame"
      const decrypted = await bobManager.decryptFrame(encryptedData);

      // Convert back to string (if it was text) or show as bytes
      try {
        const message = new TextDecoder().decode(decrypted);
        setDecryptedMessage(message);
        addLog(`✅ Frame decrypted: "${message}"`);
      } catch {
        // If it's not text (e.g., video frame data)
        setDecryptedMessage(`[Binary data: ${decrypted.byteLength} bytes]`);
        addLog(
          `✅ Frame decrypted: ${decrypted.byteLength} bytes of binary data`,
        );
      }

      // Update stats
      setStats({
        alice: aliceManager?.getStats(),
        bob: bobManager.getStats(),
      });
    } catch (err) {
      addLog(`❌ Decryption failed: ${err.message}`);
    }
  };

  // Simulate full encryption/decryption cycle
  const sendFrame = async () => {
    await encryptFrame();
    // Small delay to show the process
    setTimeout(async () => {
      await decryptFrame();
    }, 100);
  };

  // Rotate keys
  const rotateKeys = async () => {
    try {
      addLog("🔄 Performing key rotation...");

      // Alice rotates her key
      const newKeyId = await aliceManager.rotateKey();
      addLog(`✅ Alice rotated to key ${newKeyId}`);

      // In real app, Alice would signal Bob via MLS
      // For demo, Bob generates the same new key
      const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
      await bobManager.deriveKeyFromMLSSecret(
        sharedSecret.buffer,
        newKeyId,
        "Demo_SFrame_Key_Rotated",
      );
      bobManager.setActiveKey(newKeyId);
      addLog(`✅ Bob updated to key ${newKeyId}`);

      // Clean up old keys
      aliceManager.cleanupOldKeys(2);
      bobManager.cleanupOldKeys(2);

      // Update stats
      setStats({
        alice: aliceManager.getStats(),
        bob: bobManager.getStats(),
      });

      addLog("✅ Key rotation complete");
      setStatus("Keys rotated - Ready for streaming");
    } catch (err) {
      addLog(`❌ Key rotation failed: ${err.message}`);
    }
  };

  return (
    <ThemeProvider>
      <Container maxWidth="lg" sx={{ py: 3 }}>
        <Typography variant="h4" gutterBottom>
          🎥 SFrame (Secure Frame) Demo
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          End-to-End Encryption for Real-Time Media Streams
        </Typography>

        {/* Status Bar */}
        <Paper sx={{ p: 2, mb: 3, bgcolor: "action.hover" }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Typography variant="subtitle2">Status:</Typography>
            <Chip
              label={status}
              color={
                status.includes("Ready") || status.includes("rotated")
                  ? "success"
                  : "default"
              }
              size="small"
            />
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
              onClick={exchangeKeys}
              disabled={!aliceManager || status.includes("Ready")}
              size="small"
            >
              2. Exchange Keys
            </Button>
            <Button
              variant="outlined"
              onClick={rotateKeys}
              disabled={!status.includes("Ready")}
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

        {/* Statistics */}
        {stats && (
          <Paper sx={{ p: 2, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              📊 Statistics
            </Typography>
            <Box
              sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2 }}
            >
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Alice (Sender)
                </Typography>
                <Typography variant="body2">
                  Current Key ID: {stats.alice.currentKeyId}
                </Typography>
                <Typography variant="body2">
                  Frame Counter: {stats.alice.frameCounter}
                </Typography>
                <Typography variant="body2">
                  Keys Stored: {stats.alice.keyCount}
                </Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Bob (Receiver)
                </Typography>
                <Typography variant="body2">
                  Current Key ID: {stats.bob.currentKeyId}
                </Typography>
                <Typography variant="body2">
                  Frame Counter: {stats.bob.frameCounter}
                </Typography>
                <Typography variant="body2">
                  Keys Stored: {stats.bob.keyCount}
                </Typography>
              </Box>
            </Box>
          </Paper>
        )}

        {/* Demo Controls */}
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            🎬 Frame Encryption Demo
          </Typography>

          <Stack spacing={2}>
            <TextField
              fullWidth
              label="Simulated Frame Data"
              value={testMessage}
              onChange={(e) => setTestMessage(e.target.value)}
              disabled={!status.includes("Ready")}
              helperText="In a real app, this would be video/audio frame data"
            />

            <Stack direction="row" spacing={2}>
              <Button
                variant="contained"
                color="primary"
                onClick={startCameraEncryption}
                disabled={!status.includes("Ready")}
                fullWidth
              >
                📷 Capture & Encrypt Camera Frame
              </Button>
              <Button
                variant="outlined"
                onClick={encryptFrame}
                disabled={!status.includes("Ready")}
                fullWidth
              >
                📤 Encrypt Text Frame
              </Button>
              <Button
                variant="contained"
                onClick={decryptFrame}
                disabled={!encryptedData}
                fullWidth
              >
                📥 Decrypt Frame (Bob)
              </Button>
            </Stack>

            {encryptedData && (
              <Alert severity="info">
                <Typography variant="body2">
                  <strong>Encrypted:</strong> {encryptedData.length} bytes
                  (frame counter: {aliceManager?.getFrameCounter() - 1})
                </Typography>
              </Alert>
            )}

            {decryptedMessage && (
              <Alert severity="success">
                <Typography variant="body2">
                  <strong>Decrypted:</strong> {decryptedMessage}
                </Typography>
              </Alert>
            )}
          </Stack>
        </Paper>

        {/* Logs */}
        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            📋 Logs
          </Typography>
          <Box
            sx={{
              height: 200,
              overflowY: "auto",
              p: 1,
              bgcolor: "background.default",
              fontFamily: "monospace",
              fontSize: "0.875rem",
            }}
          >
            {logs.map((log, idx) => (
              <div key={idx}>{log}</div>
            ))}
          </Box>
        </Paper>

        {/* Info Box */}
        <Paper
          sx={{ p: 2, mt: 2, bgcolor: "info.main", color: "info.contrastText" }}
        >
          <Typography variant="subtitle2" gutterBottom>
            ℹ️ About SFrame:
          </Typography>
          <Typography variant="body2">
            • SFrame encrypts individual media frames (audio/video)
            <br />
            • ~10 bytes overhead per frame (very low!)
            <br />
            • Works with WebRTC Insertable Streams API
            <br />
            • Keys can be derived from MLS shared secrets
            <br />• Perfect for real-time encrypted video calls
          </Typography>
        </Paper>
      </Container>
    </ThemeProvider>
  );
};

export const Interactive = () => <SFrameDemoApp />;
