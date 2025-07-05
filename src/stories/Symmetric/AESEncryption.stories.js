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
  Tabs,
  Tab,
  IconButton,
  Slider
} from '@mui/material';
import { 
  VpnKey, 
  Lock, 
  LockOpen, 
  Speed,
  Storage,
  Refresh,
  Download,
  Upload
} from '@mui/icons-material';

export default {
  title: 'Cryptography/Symmetric/AES Encryption',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'AES-GCM symmetric encryption for fast, secure data encryption with the same key.',
      },
    },
  },
};

const AESBasicDemo = () => {
  const { 
    generateSymmetricKey, 
    deserializeSymmetricKey,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey 
  } = useCryptography();
  
  const [key, setKey] = useState(null);
  const [message, setMessage] = useState('');
  const [encrypted, setEncrypted] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [loading, setLoading] = useState(false);
  const [timings, setTimings] = useState({});

  const generateKey = async () => {
    setLoading(true);
    const start = performance.now();
    try {
      const newKey = await generateSymmetricKey();
      setKey(newKey);
      setTimings(prev => ({ ...prev, keyGen: (performance.now() - start).toFixed(2) }));
    } catch (error) {
      console.error('Error generating key:', error);
    } finally {
      setLoading(false);
    }
  };

  const encryptMessage = async () => {
    if (!key || !message) return;
    
    setLoading(true);
    const start = performance.now();
    try {
      const symmetricKey = await deserializeSymmetricKey(key);
      const result = await encryptWithSymmetricKey(message, symmetricKey);
      setEncrypted(result);
      setTimings(prev => ({ ...prev, encrypt: (performance.now() - start).toFixed(2) }));
    } catch (error) {
      console.error('Error encrypting:', error);
    } finally {
      setLoading(false);
    }
  };

  const decryptMessage = async () => {
    if (!key || !encrypted) return;
    
    setLoading(true);
    const start = performance.now();
    try {
      const symmetricKey = await deserializeSymmetricKey(key);
      const result = await decryptWithSymmetricKey(encrypted, symmetricKey);
      setDecrypted(result);
      setTimings(prev => ({ ...prev, decrypt: (performance.now() - start).toFixed(2) }));
    } catch (error) {
      console.error('Error decrypting:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="AES-GCM Symmetric Encryption"
      description="Fast encryption where the same key is used for both encryption and decryption."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          AES-GCM (Galois/Counter Mode) provides both confidentiality and authenticity. 
          It's much faster than RSA and can handle large amounts of data efficiently.
        </Alert>

        {/* Key Generation */}
        <Card>
          <CardHeader
            title="Step 1: Generate AES Key"
            subheader="256-bit symmetric key for encryption and decryption"
          />
          <CardContent>
            <Stack spacing={2}>
              <Button
                variant="contained"
                onClick={generateKey}
                disabled={loading}
                startIcon={<VpnKey />}
              >
                Generate 256-bit AES Key
              </Button>
              
              {key && (
                <Box>
                  <Stack direction="row" spacing={1} mb={1}>
                    <Chip 
                      label={`Generated in ${timings.keyGen}ms`} 
                      color="success" 
                      size="small"
                    />
                    <Chip 
                      label="AES-GCM 256-bit" 
                      color="primary" 
                      size="small"
                    />
                  </Stack>
                  <CodeDisplay
                    code={key ? JSON.stringify(key, null, 2) : 'No key available'}
                    label="AES Key (JWK Format)"
                    secret={true}
                    maxHeight="150px"
                  />
                </Box>
              )}
            </Stack>
          </CardContent>
        </Card>

        {/* Encryption */}
        {key && (
          <Card>
            <CardHeader
              title="Step 2: Encrypt Message"
              subheader="Use the symmetric key to encrypt your data"
            />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Message to Encrypt"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  multiline
                  rows={3}
                  fullWidth
                  placeholder="Enter any message (no size limit for AES)..."
                />
                
                <Stack direction="row" spacing={1} alignItems="center">
                  <Button
                    variant="contained"
                    onClick={encryptMessage}
                    disabled={loading || !message}
                    startIcon={<Lock />}
                  >
                    Encrypt Message
                  </Button>
                  {timings.encrypt && (
                    <Chip 
                      label={`${timings.encrypt}ms`} 
                      color="success" 
                      size="small"
                    />
                  )}
                </Stack>

                {encrypted && (
                  <CodeDisplay
                    code={encrypted ? JSON.stringify(encrypted, null, 2) : 'No encrypted data available'}
                    label="Encrypted Data (Base64 with IV)"
                  />
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Decryption */}
        {encrypted && (
          <Card>
            <CardHeader
              title="Step 3: Decrypt Message"
              subheader="Use the same key to decrypt the data"
            />
            <CardContent>
              <Stack spacing={2}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Button
                    variant="contained"
                    onClick={decryptMessage}
                    disabled={loading}
                    startIcon={<LockOpen />}
                  >
                    Decrypt Message
                  </Button>
                  {timings.decrypt && (
                    <Chip 
                      label={`${timings.decrypt}ms`} 
                      color="success" 
                      size="small"
                    />
                  )}
                </Stack>

                {decrypted && (
                  <Alert severity="success">
                    <Typography variant="h6" gutterBottom>
                      Decryption Successful!
                    </Typography>
                    <Typography variant="body2">
                      <strong>Original:</strong> {message}
                    </Typography>
                    <Typography variant="body2">
                      <strong>Decrypted:</strong> {decrypted}
                    </Typography>
                  </Alert>
                )}
              </Stack>
            </CardContent>
          </Card>
        )}

        <OperationStatus loading={loading} />
      </Stack>
    </CryptoDemo>
  );
};

export const BasicAES = () => (
  <CryptographyProvider>
    <AESBasicDemo />
  </CryptographyProvider>
);

const AESBulkDemo = () => {
  const { 
    generateSymmetricKey, 
    deserializeSymmetricKey,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey 
  } = useCryptography();
  
  const [key, setKey] = useState(null);
  const [dataSize, setDataSize] = useState(1000);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const generateLargeData = (size) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ';
    let result = '';
    for (let i = 0; i < size; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const performBulkTest = async () => {
    if (!key) {
      // Generate key first
      try {
        const newKey = await generateSymmetricKey();
        setKey(newKey);
        return performBulkTestWithKey(newKey);
      } catch (error) {
        console.error('Error generating key:', error);
        return;
      }
    }
    
    return performBulkTestWithKey(key);
  };

  const performBulkTestWithKey = async (testKey) => {
    setLoading(true);
    try {
      const data = generateLargeData(dataSize);
      const symmetricKey = await deserializeSymmetricKey(testKey);
      
      // Encryption
      const encryptStart = performance.now();
      const encrypted = await encryptWithSymmetricKey(data, symmetricKey);
      const encryptTime = (performance.now() - encryptStart).toFixed(2);
      
      // Decryption
      const decryptStart = performance.now();
      const decrypted = await decryptWithSymmetricKey(encrypted, symmetricKey);
      const decryptTime = (performance.now() - decryptStart).toFixed(2);
      
      setResults({
        dataSize,
        originalSize: new Blob([data]).size,
        encryptedSize: new Blob([encrypted]).size,
        encryptTime,
        decryptTime,
        success: data === decrypted,
        throughputEncrypt: (dataSize / parseFloat(encryptTime) * 1000).toFixed(0),
        throughputDecrypt: (dataSize / parseFloat(decryptTime) * 1000).toFixed(0)
      });
    } catch (error) {
      console.error('Error in bulk test:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="AES Bulk Performance Test"
      description="Test AES encryption performance with large amounts of data."
    >
      <Stack spacing={3}>
        <Box>
          <Typography gutterBottom>
            Data Size: {dataSize.toLocaleString()} characters
          </Typography>
          <Slider
            value={dataSize}
            onChange={(e, val) => setDataSize(val)}
            min={100}
            max={50000}
            step={100}
            marks={[
              { value: 100, label: '100' },
              { value: 1000, label: '1K' },
              { value: 10000, label: '10K' },
              { value: 50000, label: '50K' },
            ]}
            valueLabelDisplay="auto"
            valueLabelFormat={(value) => `${value.toLocaleString()} chars`}
          />
        </Box>

        <Button
          variant="contained"
          onClick={performBulkTest}
          disabled={loading}
          startIcon={<Speed />}
          size="large"
        >
          Run Performance Test
        </Button>

        <OperationStatus loading={loading} />

        {results && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Performance Metrics
                </Typography>
                <Stack spacing={1}>
                  <Typography variant="body2">
                    <strong>Encryption Time:</strong> {results.encryptTime}ms
                  </Typography>
                  <Typography variant="body2">
                    <strong>Decryption Time:</strong> {results.decryptTime}ms
                  </Typography>
                  <Typography variant="body2">
                    <strong>Encrypt Throughput:</strong> {results.throughputEncrypt} chars/sec
                  </Typography>
                  <Typography variant="body2">
                    <strong>Decrypt Throughput:</strong> {results.throughputDecrypt} chars/sec
                  </Typography>
                </Stack>
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Data Information
                </Typography>
                <Stack spacing={1}>
                  <Typography variant="body2">
                    <strong>Original Size:</strong> {results.originalSize.toLocaleString()} bytes
                  </Typography>
                  <Typography variant="body2">
                    <strong>Encrypted Size:</strong> {results.encryptedSize.toLocaleString()} bytes
                  </Typography>
                  <Typography variant="body2">
                    <strong>Overhead:</strong> {(results.encryptedSize - results.originalSize).toLocaleString()} bytes
                  </Typography>
                  <Typography variant="body2">
                    <strong>Verification:</strong> {results.success ? '✅ Passed' : '❌ Failed'}
                  </Typography>
                </Stack>
              </Paper>
            </Grid>
          </Grid>
        )}

        <Alert severity="info">
          <Typography variant="body2">
            AES-GCM is highly optimized in modern browsers and can handle large amounts of data efficiently. 
            The small overhead comes from the initialization vector (IV) and authentication tag.
          </Typography>
        </Alert>
      </Stack>
    </CryptoDemo>
  );
};

export const BulkEncryption = () => (
  <CryptographyProvider>
    <AESBulkDemo />
  </CryptographyProvider>
);

const AESFileDemo = () => {
  const { 
    generateSymmetricKey, 
    deserializeSymmetricKey,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey 
  } = useCryptography();
  
  const [key, setKey] = useState(null);
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [encrypted, setEncrypted] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState(0);

  const generateKey = async () => {
    setLoading(true);
    try {
      const newKey = await generateSymmetricKey();
      setKey(newKey);
    } catch (error) {
      console.error('Error generating key:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      
      const reader = new FileReader();
      reader.onload = (e) => {
        setFileContent(e.target.result);
      };
      reader.readAsText(selectedFile);
    }
  };

  const encryptFile = async () => {
    if (!key || !fileContent) return;
    
    setLoading(true);
    try {
      const symmetricKey = await deserializeSymmetricKey(key);
      const result = await encryptWithSymmetricKey(fileContent, symmetricKey);
      setEncrypted(result);
    } catch (error) {
      console.error('Error encrypting file:', error);
    } finally {
      setLoading(false);
    }
  };

  const decryptFile = async () => {
    if (!key || !encrypted) return;
    
    setLoading(true);
    try {
      const symmetricKey = await deserializeSymmetricKey(key);
      const result = await decryptWithSymmetricKey(encrypted, symmetricKey);
      setDecrypted(result);
    } catch (error) {
      console.error('Error decrypting file:', error);
    } finally {
      setLoading(false);
    }
  };

  const downloadEncrypted = () => {
    const blob = new Blob([encrypted], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${file.name}.encrypted`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <CryptoDemo
      title="File Encryption Demo"
      description="Encrypt and decrypt files using AES-GCM symmetric encryption."
    >
      <Stack spacing={3}>
        {!key && (
          <Button
            variant="contained"
            onClick={generateKey}
            disabled={loading}
            startIcon={<VpnKey />}
          >
            Generate Encryption Key
          </Button>
        )}

        {key && (
          <Stack spacing={2}>
            <Box>
              <input
                accept="*/*"
                style={{ display: 'none' }}
                id="file-upload"
                type="file"
                onChange={handleFileSelect}
              />
              <label htmlFor="file-upload">
                <Button
                  variant="outlined"
                  component="span"
                  startIcon={<Upload />}
                >
                  Select File to Encrypt
                </Button>
              </label>
            </Box>

            {file && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Selected File
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Name: {file.name} | Size: {(file.size / 1024).toFixed(2)} KB
                </Typography>
              </Paper>
            )}

            {fileContent && (
              <Stack direction="row" spacing={2}>
                <Button
                  variant="contained"
                  onClick={encryptFile}
                  disabled={loading}
                  startIcon={<Lock />}
                >
                  Encrypt File
                </Button>
                
                {encrypted && (
                  <>
                    <Button
                      variant="contained"
                      onClick={decryptFile}
                      disabled={loading}
                      startIcon={<LockOpen />}
                    >
                      Decrypt File
                    </Button>
                    
                    <Button
                      variant="outlined"
                      onClick={downloadEncrypted}
                      startIcon={<Download />}
                    >
                      Download Encrypted
                    </Button>
                  </>
                )}
              </Stack>
            )}

            {(fileContent || encrypted || decrypted) && (
              <Box>
                <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
                  {fileContent && <Tab label="Original" />}
                  {encrypted && <Tab label="Encrypted" />}
                  {decrypted && <Tab label="Decrypted" />}
                </Tabs>
                
                <Box sx={{ mt: 2 }}>
                  {activeTab === 0 && fileContent && (
                    <CodeDisplay
                      code={fileContent}
                      label="Original File Content"
                      maxHeight="300px"
                    />
                  )}
                  {activeTab === 1 && encrypted && (
                    <CodeDisplay
                      code={encrypted ? JSON.stringify(encrypted, null, 2) : 'No encrypted data available'}
                      label="Encrypted File Content"
                      maxHeight="300px"
                    />
                  )}
                  {activeTab === 2 && decrypted && (
                    <Box>
                      <Alert severity="success" sx={{ mb: 2 }}>
                        File decrypted successfully! Content matches original: {fileContent === decrypted ? '✅' : '❌'}
                      </Alert>
                      <CodeDisplay
                        code={decrypted}
                        label="Decrypted File Content"
                        maxHeight="300px"
                      />
                    </Box>
                  )}
                </Box>
              </Box>
            )}
          </Stack>
        )}

        <OperationStatus loading={loading} />

        <Alert severity="info">
          <Typography variant="body2">
            <strong>File Encryption Use Cases:</strong>
          </Typography>
          <Typography component="ul" variant="body2" sx={{ mt: 1, mb: 0 }}>
            <li>Protecting sensitive documents</li>
            <li>Secure file storage and backup</li>
            <li>Encrypted file sharing</li>
            <li>Data at rest protection</li>
          </Typography>
        </Alert>
      </Stack>
    </CryptoDemo>
  );
};

export const FileEncryption = () => (
  <CryptographyProvider>
    <AESFileDemo />
  </CryptographyProvider>
);