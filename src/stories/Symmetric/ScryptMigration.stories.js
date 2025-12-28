import React, { useState } from "react";
import {
  CryptographyProvider,
  useCryptography,
} from "../components/Cryptography";
import {
  CryptoDemo,
  CodeDisplay,
  OperationStatus,
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
} from "ui";

export default {
  title: "Cryptography/Symmetric/Scrypt Migration",
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component:
          "Demonstration of Scrypt key derivation replacing PBKDF2 for GPU/ASIC-resistant password-based encryption.",
      },
    },
  },
};

const ScryptMigrationDemo = () => {
  const { encryptFile, decryptFile } = useCryptography();
  const [password, setPassword] = useState("my-secure-password");
  const [message, setMessage] = useState("Hello, Scrypt encryption!");
  const [encrypted, setEncrypted] = useState(null);
  const [decrypted, setDecrypted] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [timings, setTimings] = useState({});

  const handleEncrypt = async () => {
    if (!password || !message) {
      setError("Please provide both password and message");
      return;
    }

    setLoading(true);
    setError(null);
    setDecrypted(null);
    const start = performance.now();

    try {
      const result = await encryptFile(message, password, "test.txt");
      setEncrypted(result);
      setTimings((prev) => ({
        ...prev,
        encrypt: (performance.now() - start).toFixed(2),
      }));
    } catch (err) {
      setError(`Encryption failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!encrypted || !password) {
      setError("Please encrypt a message first");
      return;
    }

    setLoading(true);
    setError(null);
    const start = performance.now();

    try {
      const result = await decryptFile(encrypted, password);
      const textContent = new TextDecoder().decode(result.data);
      setDecrypted(textContent);
      setTimings((prev) => ({
        ...prev,
        decrypt: (performance.now() - start).toFixed(2),
      }));
    } catch (err) {
      setError(`Decryption failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo title="Scrypt Key Derivation Migration">
      <Stack spacing={3}>
        <Alert severity="info">
          <Typography variant="body2">
            <strong>Scrypt Migration:</strong> This demo shows the migration
            from PBKDF2 to Scrypt for key derivation. Scrypt is GPU/ASIC
            resistant and provides better security against hardware-accelerated
            attacks.
          </Typography>
        </Alert>

        <Card>
          <CardHeader title="Scrypt Parameters" />
          <CardContent>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, bgcolor: "background.default" }}>
                  <Typography variant="caption" color="text.secondary">
                    N (CPU/Memory Cost)
                  </Typography>
                  <Typography variant="h6">32,768</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, bgcolor: "background.default" }}>
                  <Typography variant="caption" color="text.secondary">
                    r (Block Size)
                  </Typography>
                  <Typography variant="h6">8</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Paper sx={{ p: 2, bgcolor: "background.default" }}>
                  <Typography variant="caption" color="text.secondary">
                    p (Parallelization)
                  </Typography>
                  <Typography variant="h6">1</Typography>
                </Paper>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        <Card>
          <CardHeader title="Encryption Test" />
          <CardContent>
            <Stack spacing={2}>
              <TextField
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                fullWidth
              />
              <TextField
                label="Message"
                multiline
                rows={3}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                fullWidth
              />
              <Button
                variant="contained"
                onClick={handleEncrypt}
                disabled={loading || !password || !message}
              >
                Encrypt with Scrypt
              </Button>
              {timings.encrypt && (
                <Typography variant="caption" color="text.secondary">
                  Encryption time: {timings.encrypt}ms
                </Typography>
              )}
            </Stack>
          </CardContent>
        </Card>

        {encrypted && (
          <Card>
            <CardHeader title="Encrypted Result" />
            <CardContent>
              <Stack spacing={2}>
                <OperationStatus
                  status="success"
                  message="Encryption successful"
                />
                <CodeDisplay
                  code={JSON.stringify(
                    {
                      encryptedData:
                        encrypted.encryptedData.substring(0, 50) + "...",
                      iv: encrypted.iv.substring(0, 20) + "...",
                      salt: encrypted.salt.substring(0, 20) + "...",
                      fileName: encrypted.fileName,
                      timestamp: encrypted.timestamp,
                    },
                    null,
                    2,
                  )}
                  language="json"
                />
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={handleDecrypt}
                  disabled={loading}
                >
                  Decrypt
                </Button>
                {timings.decrypt && (
                  <Typography variant="caption" color="text.secondary">
                    Decryption time: {timings.decrypt}ms
                  </Typography>
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        {decrypted && (
          <Card>
            <CardHeader title="Decrypted Result" />
            <CardContent>
              <OperationStatus
                status="success"
                message="Decryption successful"
              />
              <Paper sx={{ p: 2, mt: 2, bgcolor: "background.default" }}>
                <Typography variant="body1">{decrypted}</Typography>
              </Paper>
            </CardContent>
          </Card>
        )}

        {error && <Alert severity="error">{error}</Alert>}

        <Card>
          <CardHeader title="Security Features" />
          <CardContent>
            <Stack spacing={1}>
              <Chip label="GPU/ASIC Resistant" color="success" size="small" />
              <Chip label="Memory Hard" color="success" size="small" />
              <Chip
                label="Zeroization of Password Buffers"
                color="success"
                size="small"
              />
              <Chip
                label="Random Salt per Encryption"
                color="success"
                size="small"
              />
            </Stack>
          </CardContent>
        </Card>
      </Stack>
    </CryptoDemo>
  );
};

export const ScryptDemo = {
  render: () => (
    <CryptographyProvider>
      <ScryptMigrationDemo />
    </CryptographyProvider>
  ),
};
