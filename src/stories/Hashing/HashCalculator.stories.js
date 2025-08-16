import React, { useState, useEffect, useCallback } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import {
  CryptoDemo,
  CodeDisplay,
  OperationStatus,
  Button,
  TextField,
  Box,
  Typography,
  Stack,
  Tab,
  Tabs,
  Paper,
  Chip,
  IconButton,
  InputAdornment,
  Alert,
  Grid,
  Card,
  CardContent,
  Tag,
  Upload,
  Clear,
  Speed,
  CheckCircle,
  Cancel
} from 'ui';

export default {
  title: 'Cryptography/Hashing/Hash Calculator',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'Calculate cryptographic hashes using SHA-256, SHA-512, and SHA3-512 algorithms.',
      },
    },
  },
};

const HashCalculatorDemo = () => {
  const { sha256Hash, sha512Hash, sha3_512Hash } = useCryptography();
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState({
    sha256: '',
    sha512: '',
    sha3_512: ''
  });
  const [loading, setLoading] = useState(false);
  const [timings, setTimings] = useState({});
  const [activeTab, setActiveTab] = useState(0);

  const calculateHashes = useCallback(async () => {
    if (!input) return;
    
    setLoading(true);
    const newTimings = {};
    
    try {
      // SHA-256
      const start256 = performance.now();
      const hash256 = await sha256Hash(input);
      newTimings.sha256 = (performance.now() - start256).toFixed(2);
      
      // SHA-512
      const start512 = performance.now();
      const hash512 = await sha512Hash(input);
      newTimings.sha512 = (performance.now() - start512).toFixed(2);
      
      // SHA3-512
      const start3_512 = performance.now();
      const hash3_512 = await sha3_512Hash(input);
      newTimings.sha3_512 = (performance.now() - start3_512).toFixed(2);
      
      setHashes({
        sha256: hash256,
        sha512: hash512,
        sha3_512: hash3_512
      });
      setTimings(newTimings);
    } catch (error) {
      console.error('Error calculating hashes:', error);
    } finally {
      setLoading(false);
    }
  }, [input, sha256Hash, sha512Hash, sha3_512Hash]);

  // Auto-calculate on input change (debounced)
  useEffect(() => {
    if (input) {
      const timer = setTimeout(() => {
        calculateHashes();
      }, 300);
      return () => clearTimeout(timer);
    } else {
      setHashes({ sha256: '', sha512: '', sha3_512: '' });
      setTimings({});
    }
  }, [input, calculateHashes]);

  const hashAlgorithms = [
    { 
      id: 'sha256', 
      name: 'SHA-256', 
      bits: 256,
      description: 'Most common, fast, suitable for general use'
    },
    { 
      id: 'sha512', 
      name: 'SHA-512', 
      bits: 512,
      description: 'Stronger variant, better for sensitive data'
    },
    { 
      id: 'sha3_512', 
      name: 'SHA3-512', 
      bits: 512,
      description: 'Latest standard, maximum security'
    }
  ];

  return (
    <CryptoDemo
      title="Interactive Hash Calculator"
      description="Calculate and compare different hash algorithms in real-time."
    >
      <Stack spacing={3}>
        <TextField
          label="Input Text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          multiline
          rows={4}
          fullWidth
          variant="outlined"
          placeholder="Enter text to hash..."
          InputProps={{
            endAdornment: input && (
              <InputAdornment position="end">
                <IconButton onClick={() => setInput('')} edge="end">
                  <Clear />
                </IconButton>
              </InputAdornment>
            )
          }}
        />

        <OperationStatus loading={loading} />

        {input && (
          <>
            <Typography variant="subtitle2" color="text.secondary">
              Input length: {input.length} characters | {new Blob([input]).size} bytes
            </Typography>

            <Tabs 
              value={activeTab} 
              onChange={(e, val) => setActiveTab(val)}
              variant="fullWidth"
            >
              {hashAlgorithms.map((algo, idx) => (
                <Tab 
                  key={algo.id} 
                  label={algo.name}
                  icon={timings[algo.id] && (
                    <Chip 
                      size="small" 
                      label={`${timings[algo.id]}ms`}
                      color="primary"
                      variant="outlined"
                    />
                  )}
                />
              ))}
            </Tabs>

            <Box sx={{ mt: 2 }}>
              {hashAlgorithms.map((algo, idx) => (
                <Box
                  key={algo.id}
                  hidden={activeTab !== idx}
                  sx={{ p: 2 }}
                >
                  <Stack spacing={2}>
                    <Typography variant="body2" color="text.secondary">
                      {algo.description}
                    </Typography>
                    
                    {hashes[algo.id] && (
                      <>
                        <CodeDisplay
                          code={hashes[algo.id]}
                          label={`${algo.name} Hash (${algo.bits} bits / ${algo.bits / 8} bytes)`}
                        />
                        
                        <Typography variant="caption" color="text.secondary">
                          Hex length: {hashes[algo.id].length} characters
                        </Typography>
                      </>
                    )}
                  </Stack>
                </Box>
              ))}
            </Box>
          </>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const Default = () => (
  <CryptographyProvider>
    <HashCalculatorDemo />
  </CryptographyProvider>
);

const FileHashDemo = () => {
  const { sha256Hash, sha512Hash, sha3_512Hash } = useCryptography();
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [hashes, setHashes] = useState({});
  const [loading, setLoading] = useState(false);

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

  const calculateFileHashes = useCallback(async () => {
    if (!fileContent) return;
    
    setLoading(true);
    try {
      const [hash256, hash512, hash3_512] = await Promise.all([
        sha256Hash(fileContent),
        sha512Hash(fileContent),
        sha3_512Hash(fileContent)
      ]);
      
      setHashes({
        sha256: hash256,
        sha512: hash512,
        sha3_512: hash3_512
      });
    } catch (error) {
      console.error('Error hashing file:', error);
    } finally {
      setLoading(false);
    }
  }, [fileContent, sha256Hash, sha512Hash, sha3_512Hash]);

  useEffect(() => {
    if (fileContent) {
      calculateFileHashes();
    }
  }, [fileContent, calculateFileHashes]);

  return (
    <CryptoDemo
      title="File Hash Calculator"
      description="Calculate cryptographic hashes of files for integrity verification."
    >
      <Stack spacing={3}>
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
              variant="contained"
              component="span"
              startIcon={<Upload />}
            >
              Select File to Hash
            </Button>
          </label>
        </Box>

        {file && (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              File Information
            </Typography>
            <Grid container spacing={1}>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Name: {file.name}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Size: {(file.size / 1024).toFixed(2)} KB
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="text.secondary">
                  Type: {file.type || 'Unknown'}
                </Typography>
              </Grid>
            </Grid>
          </Paper>
        )}

        <OperationStatus loading={loading} />

        {Object.keys(hashes).length > 0 && (
          <Stack spacing={2}>
            {Object.entries(hashes).map(([algo, hash]) => (
              <CodeDisplay
                key={algo}
                code={hash}
                label={algo.toUpperCase().replace('_', '-') + ' Hash'}
              />
            ))}
          </Stack>
        )}

        {file && (
          <Alert severity="info">
            <Typography variant="body2">
              File hashes are commonly used for:
            </Typography>
            <Typography component="ul" variant="body2" sx={{ mt: 1, mb: 0 }}>
              <li>Verifying file integrity after download</li>
              <li>Detecting file tampering or corruption</li>
              <li>Creating unique file identifiers</li>
              <li>Deduplication in storage systems</li>
            </Typography>
          </Alert>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const FileHashing = () => (
  <CryptographyProvider>
    <FileHashDemo />
  </CryptographyProvider>
);

const HashVerificationDemo = () => {
  const { sha256Hash, sha512Hash, sha3_512Hash } = useCryptography();
  const [input, setInput] = useState('');
  const [knownHash, setKnownHash] = useState('');
  const [algorithm, setAlgorithm] = useState('sha256');
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const verifyHash = async () => {
    if (!input || !knownHash) return;
    
    setLoading(true);
    try {
      let calculatedHash;
      switch (algorithm) {
        case 'sha256':
          calculatedHash = await sha256Hash(input);
          break;
        case 'sha512':
          calculatedHash = await sha512Hash(input);
          break;
        case 'sha3_512':
          calculatedHash = await sha3_512Hash(input);
          break;
      }
      
      const matches = calculatedHash.toLowerCase() === knownHash.toLowerCase();
      setVerificationResult({
        matches,
        calculated: calculatedHash,
        provided: knownHash
      });
    } catch (error) {
      console.error('Error verifying hash:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Hash Verification"
      description="Verify if a given hash matches your input data."
    >
      <Stack spacing={3}>
        <TextField
          label="Input Text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          multiline
          rows={3}
          fullWidth
          variant="outlined"
        />

        <TextField
          label="Known Hash to Verify"
          value={knownHash}
          onChange={(e) => setKnownHash(e.target.value)}
          fullWidth
          variant="outlined"
          placeholder="Paste the hash to verify..."
        />

        <TextField
          select
          label="Hash Algorithm"
          value={algorithm}
          onChange={(e) => setAlgorithm(e.target.value)}
          fullWidth
          SelectProps={{ native: true }}
        >
          <option value="sha256">SHA-256</option>
          <option value="sha512">SHA-512</option>
          <option value="sha3_512">SHA3-512</option>
        </TextField>

        <Button
          variant="contained"
          onClick={verifyHash}
          disabled={loading || !input || !knownHash}
          startIcon={<Tag />}
        >
          Verify Hash
        </Button>

        <OperationStatus loading={loading} />

        {verificationResult && (
          <Card variant={verificationResult.matches ? "outlined" : "elevation"}>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={2} mb={2}>
                {verificationResult.matches ? (
                  <>
                    <CheckCircle color="success" fontSize="large" />
                    <Typography variant="h6" color="success.main">
                      Hash Verified Successfully!
                    </Typography>
                  </>
                ) : (
                  <>
                    <Cancel color="error" fontSize="large" />
                    <Typography variant="h6" color="error.main">
                      Hash Verification Failed
                    </Typography>
                  </>
                )}
              </Stack>
              
              <Stack spacing={2}>
                <CodeDisplay
                  code={verificationResult.calculated}
                  label="Calculated Hash"
                />
                <CodeDisplay
                  code={verificationResult.provided}
                  label="Provided Hash"
                />
              </Stack>
            </CardContent>
          </Card>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const HashVerification = () => (
  <CryptographyProvider>
    <HashVerificationDemo />
  </CryptographyProvider>
);