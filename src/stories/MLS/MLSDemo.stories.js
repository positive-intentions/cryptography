/**
 * MLS (Message Layer Security) Demo
 * Interactive demonstration of RFC 9420 end-to-end encrypted group messaging
 * Uses real ts-mls library implementation
 */

import React, { useState } from "react";
import { MLSManager } from "../../crypto/MLS/MLSManager.tsx";
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
} from "ui";

export default {
  title: "MLS/MLSDemo",
  parameters: {
    layout: "fullscreen",
  },
};

const MLSDemoApp = () => {
  const [aliceManager, setAliceManager] = useState(null);
  const [bobManager, setBobManager] = useState(null);
  const [charlieManager, setCharlieManager] = useState(null);

  const [groupId] = useState("secure-group");
  const [aliceMessages, setAliceMessages] = useState([]);
  const [bobMessages, setBobMessages] = useState([]);
  const [charlieMessages, setCharlieMessages] = useState([]);

  const [aliceInput, setAliceInput] = useState("");
  const [bobInput, setBobInput] = useState("");
  const [charlieInput, setCharlieInput] = useState("");

  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState("Not initialized");
  const [groupInfo, setGroupInfo] = useState(null);

  const addLog = (message, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { time: timestamp, message, type }]);
  };

  // Initialize MLS managers
  const initializeManagers = async () => {
    try {
      setStatus("Initializing...");
      setError(null);
      addLog("🔐 Initializing MLS managers...", "info");

      // Create managers
      const alice = new MLSManager("alice@example.com");
      const bob = new MLSManager("bob@example.com");
      const charlie = new MLSManager("charlie@example.com");

      // Initialize them
      await alice.initialize();
      addLog(
        "✅ Alice initialized with MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "success",
      );

      await bob.initialize();
      addLog("✅ Bob initialized", "success");

      await charlie.initialize();
      addLog("✅ Charlie initialized", "success");

      setAliceManager(alice);
      setBobManager(bob);
      setCharlieManager(charlie);

      setStatus("Initialized - Ready to create group");
      addLog("🎉 All managers initialized successfully!", "success");
    } catch (err) {
      addLog(`❌ Initialization failed: ${err.message}`, "error");
    }
  };

  // Create group and add members
  const createGroup = async () => {
    try {
      if (!aliceManager || !bobManager || !charlieManager) {
        throw new Error("Managers not initialized");
      }

      setStatus("Creating group...");
      setError(null);
      addLog(`📝 Alice creating group: ${groupId}`, "info");

      // Alice creates the group
      const aliceGroupInfo = await aliceManager.createGroup(groupId);
      addLog(`✅ Group created at epoch ${aliceGroupInfo.epoch}`, "success");

      // Add Bob AND Charlie together (single commit = all stay in sync!)
      addLog("🔑 Adding Bob and Charlie to group...", "info");
      const bobKeyPackage = bobManager.getKeyPackage();
      const charlieKeyPackage = charlieManager.getKeyPackage();

      // Add both members in one operation
      const addResult = await aliceManager.addMembers(groupId, [
        bobKeyPackage,
        charlieKeyPackage,
      ]);

      // Process welcome messages
      await bobManager.processWelcome(addResult.welcome, addResult.ratchetTree);
      await charlieManager.processWelcome(
        addResult.welcome,
        addResult.ratchetTree,
      );

      addLog("✅ Bob and Charlie joined the group", "success");

      // Verify all members are at the same epoch
      const aliceInfo = await aliceManager.getGroupKeyInfo(groupId);
      const bobInfo = await bobManager.getGroupKeyInfo(groupId);
      const charlieInfo = await charlieManager.getGroupKeyInfo(groupId);
      addLog(
        `📊 Epoch verification - Alice: ${aliceInfo.epoch}, Bob: ${bobInfo.epoch}, Charlie: ${charlieInfo.epoch}`,
        "success",
      );

      if (
        aliceInfo.epoch === bobInfo.epoch &&
        bobInfo.epoch === charlieInfo.epoch
      ) {
        addLog("✅ All members synchronized at same epoch!", "success");
      } else {
        addLog(
          "⚠️ WARNING: Members at different epochs - messages may fail",
          "error",
        );
      }

      // Get final group info
      const finalGroupInfo = await aliceManager.getGroupKeyInfo(groupId);
      setGroupInfo(finalGroupInfo);

      setStatus("Group ready - Epoch " + finalGroupInfo.epoch);
      addLog(
        `🎉 Group setup complete! Current epoch: ${finalGroupInfo.epoch}`,
        "success",
      );
      addLog(`🔑 Tree Hash: ${finalGroupInfo.treeHash}`, "info");
    } catch (err) {
      addLog(`❌ Group creation failed: ${err.message}`, "error");
    }
  };

  // Alice sends a message
  const sendAliceMessage = async () => {
    try {
      if (!aliceInput.trim()) return;

      addLog(`📤 Alice encrypting message...`, "info");
      const envelope = await aliceManager.encryptMessage(groupId, aliceInput);

      // Add to Alice's view
      setAliceMessages((prev) => [
        ...prev,
        { from: "Alice", text: aliceInput, encrypted: false },
      ]);

      // Bob and Charlie decrypt
      const bobDecrypted = await bobManager.decryptMessage(envelope);
      setBobMessages((prev) => [
        ...prev,
        { from: "Alice", text: bobDecrypted, encrypted: true },
      ]);

      const charlieDecrypted = await charlieManager.decryptMessage(envelope);
      setCharlieMessages((prev) => [
        ...prev,
        { from: "Alice", text: charlieDecrypted, encrypted: true },
      ]);

      addLog(
        `✅ Message delivered and decrypted by Bob and Charlie`,
        "success",
      );
      setAliceInput("");
    } catch (err) {
      addLog(`❌ Send failed: ${err.message}`, "error");
    }
  };

  // Bob sends a message
  const sendBobMessage = async () => {
    try {
      if (!bobInput.trim()) return;

      addLog(`📤 Bob encrypting message...`, "info");
      const envelope = await bobManager.encryptMessage(groupId, bobInput);

      setBobMessages((prev) => [
        ...prev,
        { from: "Bob", text: bobInput, encrypted: false },
      ]);

      const aliceDecrypted = await aliceManager.decryptMessage(envelope);
      setAliceMessages((prev) => [
        ...prev,
        { from: "Bob", text: aliceDecrypted, encrypted: true },
      ]);

      const charlieDecrypted = await charlieManager.decryptMessage(envelope);
      setCharlieMessages((prev) => [
        ...prev,
        { from: "Bob", text: charlieDecrypted, encrypted: true },
      ]);

      addLog(
        `✅ Message delivered and decrypted by Alice and Charlie`,
        "success",
      );
      setBobInput("");
    } catch (err) {
      addLog(`❌ Send failed: ${err.message}`, "error");
    }
  };

  // Charlie sends a message
  const sendCharlieMessage = async () => {
    try {
      if (!charlieInput.trim()) return;

      addLog(`📤 Charlie encrypting message...`, "info");
      const envelope = await charlieManager.encryptMessage(
        groupId,
        charlieInput,
      );

      setCharlieMessages((prev) => [
        ...prev,
        { from: "Charlie", text: charlieInput, encrypted: false },
      ]);

      const aliceDecrypted = await aliceManager.decryptMessage(envelope);
      setAliceMessages((prev) => [
        ...prev,
        { from: "Charlie", text: aliceDecrypted, encrypted: true },
      ]);

      const bobDecrypted = await bobManager.decryptMessage(envelope);
      setBobMessages((prev) => [
        ...prev,
        { from: "Charlie", text: bobDecrypted, encrypted: true },
      ]);

      addLog(`✅ Message delivered and decrypted by Alice and Bob`, "success");
      setCharlieInput("");
    } catch (err) {
      addLog(`❌ Send failed: ${err.message}`, "error");
    }
  };

  // Perform key rotation
  const rotateKeys = async () => {
    try {
      setError(null);
      addLog("🔄 Alice performing key rotation...", "info");

      const epochBefore = groupInfo?.epoch;

      const commitMessage = await aliceManager.updateKey(groupId);
      await bobManager.processCommit(groupId, commitMessage);
      await charlieManager.processCommit(groupId, commitMessage);

      const updatedInfo = await aliceManager.getGroupKeyInfo(groupId);
      setGroupInfo(updatedInfo);
      setStatus("Group ready - Epoch " + updatedInfo.epoch);

      addLog(
        `✅ Key rotation successful: ${epochBefore} → ${updatedInfo.epoch}`,
        "success",
      );
      addLog(`🔑 New Tree Hash: ${updatedInfo.treeHash}`, "info");
      addLog(
        "⚡ Forward secrecy maintained - old keys cannot decrypt new messages",
        "success",
      );
    } catch (err) {
      addLog(`❌ Key rotation failed: ${err.message}`, "error");
    }
  };

  return (
    <ThemeProvider>
      <Container maxWidth="xl" sx={{ py: 3 }}>
        <Typography variant="h4" gutterBottom>
          🔐 MLS (Message Layer Security) Demo
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          RFC 9420 - Real Implementation using ts-mls
        </Typography>

        {/* Status Bar */}
        <Paper sx={{ p: 2, mb: 3, bgcolor: "action.hover" }}>
          <Stack
            direction="row"
            spacing={2}
            alignItems="center"
            flexWrap="wrap"
          >
            <Typography variant="subtitle2">Status:</Typography>
            <Chip
              label={status}
              color={status.includes("ready") ? "success" : "default"}
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
              onClick={createGroup}
              disabled={!aliceManager || status.includes("ready")}
              size="small"
              color="primary"
            >
              2. Create Group
            </Button>
            <Button
              variant="outlined"
              onClick={rotateKeys}
              disabled={!status.includes("ready")}
              size="small"
              color="secondary"
            >
              🔄 Rotate Keys
            </Button>
          </Stack>
        </Paper>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Group Info Card */}
        {groupInfo && (
          <Card sx={{ mb: 3, bgcolor: "success.dark", color: "white" }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                📊 Group Information
              </Typography>
              <Stack spacing={1}>
                <Typography variant="body2">
                  <strong>Group ID:</strong> {groupInfo.groupId}
                </Typography>
                <Typography variant="body2">
                  <strong>Current Epoch:</strong> {groupInfo.epoch}
                </Typography>
                <Typography variant="body2">
                  <strong>Ciphersuite:</strong> {groupInfo.cipherSuite}
                </Typography>
                <Typography variant="body2">
                  <strong>Tree Hash:</strong> {groupInfo.treeHash}
                </Typography>
                <Typography variant="body2">
                  <strong>Members:</strong> {groupInfo.members.join(", ")}
                </Typography>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Chat Windows */}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", md: "1fr 1fr 1fr" },
            gap: 2,
            mb: 3,
          }}
        >
          {/* Alice */}
          <Paper sx={{ p: 2 }}>
            <Typography
              variant="h6"
              gutterBottom
              sx={{ color: "primary.main" }}
            >
              👩 Alice
            </Typography>
            <Box
              sx={{
                height: 300,
                overflowY: "auto",
                mb: 2,
                p: 1,
                bgcolor: "background.default",
                borderRadius: 1,
              }}
            >
              {aliceMessages.map((msg, idx) => (
                <Box
                  key={idx}
                  sx={{
                    mb: 1,
                    p: 1,
                    bgcolor:
                      msg.from === "Alice" ? "action.hover" : "transparent",
                    borderRadius: 1,
                  }}
                >
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && "🔒"}
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
                onKeyPress={(e) => e.key === "Enter" && sendAliceMessage()}
                placeholder="Type message..."
                disabled={!status.includes("ready")}
              />
              <Button
                onClick={sendAliceMessage}
                disabled={!status.includes("ready")}
                variant="contained"
                size="small"
              >
                Send
              </Button>
            </Stack>
          </Paper>

          {/* Bob */}
          <Paper sx={{ p: 2 }}>
            <Typography
              variant="h6"
              gutterBottom
              sx={{ color: "secondary.main" }}
            >
              👨 Bob
            </Typography>
            <Box
              sx={{
                height: 300,
                overflowY: "auto",
                mb: 2,
                p: 1,
                bgcolor: "background.default",
                borderRadius: 1,
              }}
            >
              {bobMessages.map((msg, idx) => (
                <Box
                  key={idx}
                  sx={{
                    mb: 1,
                    p: 1,
                    bgcolor:
                      msg.from === "Bob" ? "action.hover" : "transparent",
                    borderRadius: 1,
                  }}
                >
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && "🔒"}
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
                onKeyPress={(e) => e.key === "Enter" && sendBobMessage()}
                placeholder="Type message..."
                disabled={!status.includes("ready")}
              />
              <Button
                onClick={sendBobMessage}
                disabled={!status.includes("ready")}
                variant="contained"
                size="small"
              >
                Send
              </Button>
            </Stack>
          </Paper>

          {/* Charlie */}
          <Paper sx={{ p: 2 }}>
            <Typography
              variant="h6"
              gutterBottom
              sx={{ color: "warning.main" }}
            >
              🧑 Charlie
            </Typography>
            <Box
              sx={{
                height: 300,
                overflowY: "auto",
                mb: 2,
                p: 1,
                bgcolor: "background.default",
                borderRadius: 1,
              }}
            >
              {charlieMessages.map((msg, idx) => (
                <Box
                  key={idx}
                  sx={{
                    mb: 1,
                    p: 1,
                    bgcolor:
                      msg.from === "Charlie" ? "action.hover" : "transparent",
                    borderRadius: 1,
                  }}
                >
                  <Typography variant="caption" color="text.secondary">
                    {msg.from} {msg.encrypted && "🔒"}
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
                onKeyPress={(e) => e.key === "Enter" && sendCharlieMessage()}
                placeholder="Type message..."
                disabled={!status.includes("ready")}
              />
              <Button
                onClick={sendCharlieMessage}
                disabled={!status.includes("ready")}
                variant="contained"
                size="small"
              >
                Send
              </Button>
            </Stack>
          </Paper>
        </Box>

        {/* Logs */}
        <Paper sx={{ p: 2, mb: 2 }}>
          <Typography variant="h6" gutterBottom>
            📋 Activity Log
          </Typography>
          <Box
            sx={{
              height: 200,
              overflowY: "auto",
              p: 1,
              bgcolor: "background.default",
              fontFamily: "monospace",
              fontSize: "0.8rem",
            }}
          >
            <List dense>
              {logs.map((log, idx) => (
                <ListItem key={idx} sx={{ py: 0.5 }}>
                  <ListItemText
                    primary={`[${log.time}] ${log.message}`}
                    primaryTypographyProps={{
                      color:
                        log.type === "error"
                          ? "error"
                          : log.type === "success"
                            ? "success.main"
                            : "text.primary",
                      fontFamily: "monospace",
                      fontSize: "0.8rem",
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </Paper>

        {/* Info Box */}
        <Paper sx={{ p: 2, bgcolor: "info.dark", color: "white" }}>
          <Typography variant="subtitle2" gutterBottom>
            ℹ️ How MLS Works:
          </Typography>
          <Typography variant="body2" component="div">
            <ol style={{ paddingLeft: "1.5rem", margin: 0 }}>
              <li>
                <strong>Initialize:</strong> Creates MLS managers with X25519 +
                Ed25519 keys
              </li>
              <li>
                <strong>Create Group:</strong> Alice creates group and adds Bob
                & Charlie via key packages
              </li>
              <li>
                <strong>Messaging:</strong> All messages encrypted with group
                ratchet tree (forward secrecy)
              </li>
              <li>
                <strong>Key Rotation:</strong> Updates epoch and tree hash for
                enhanced security
              </li>
              <li>
                <strong>🔒 Icon:</strong> Indicates message was encrypted and
                decrypted using MLS
              </li>
            </ol>
          </Typography>
          <Divider sx={{ my: 2, bgcolor: "white", opacity: 0.3 }} />
          <Typography variant="caption">
            <strong>Technical Details:</strong> This uses RFC 9420 MLS protocol
            with MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 ciphersuite via
            ts-mls library. Each message triggers key ratcheting for perfect
            forward secrecy.
          </Typography>
        </Paper>
      </Container>
    </ThemeProvider>
  );
};

export const Interactive = () => <MLSDemoApp />;
