import React, { useState } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import {
  Button,
  TextField,
  Box,
  Typography,
  Slider,
  Stack,
  RefreshIcon as Refresh,
  Casino,
  CryptoDemo,
  CodeDisplay,
  OperationStatus
} from 'ui';

export default {
  title: 'Cryptography/Random Generation/Basic Random',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'Generate cryptographically secure random strings using the browser\'s crypto.getRandomValues() API.',
      },
    },
  },
};

const RandomStringDemo = () => {
  const { randomString } = useCryptography();
  const [length, setLength] = useState(32);
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [customSalt, setCustomSalt] = useState('');

  const generateRandom = async () => {
    setLoading(true);
    try {
      const random = await randomString(length, customSalt || undefined);
      setResult(random);
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Cryptographically Secure Random Strings"
      description="Generate random strings using crypto.getRandomValues() for maximum security. Perfect for tokens, IDs, and passwords."
    >
        <Box className="demo-section">
          <Stack spacing={3}>
            <Box>
              <Typography gutterBottom>String Length: {length} characters</Typography>
              <Slider
                value={length}
                onChange={(e, val) => setLength(val)}
                min={8}
                max={128}
                marks={[
                  { value: 8, label: '8' },
                  { value: 32, label: '32' },
                  { value: 64, label: '64' },
                  { value: 128, label: '128' },
                ]}
              />
            </Box>

            <TextField
              label="Custom Salt (optional)"
              value={customSalt}
              onChange={(e) => setCustomSalt(e.target.value)}
              fullWidth
              helperText="Add entropy to the random generation"
              variant="outlined"
            />

            <Button
              variant="contained"
              onClick={generateRandom}
              disabled={loading}
              startIcon={<Casino />}
              size="large"
            >
              Generate Random String
            </Button>

            <OperationStatus loading={loading} />

            {result && (
              <CodeDisplay
                code={result}
                label={`Random String (${result.length} characters)`}
              />
            )}
          </Stack>
        </Box>

        <Box className="demo-section" sx={{ mt: 4 }}>
          <Typography variant="h6" gutterBottom>
            How It Works
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            This function uses the Web Crypto API's <code>crypto.getRandomValues()</code> method
            to generate cryptographically strong random values. The browser's crypto module
            seeds from the operating system's entropy pool, making it suitable for security-sensitive
            applications.
          </Typography>

          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Use Cases
          </Typography>
          <Typography component="ul" variant="body2" color="text.secondary">
            <li>Session tokens and API keys</li>
            <li>Temporary passwords</li>
            <li>Unique identifiers</li>
            <li>Nonces for cryptographic operations</li>
            <li>Salt generation for hashing</li>
          </Typography>
        </Box>
      </CryptoDemo>
  );
};

export const Default = () => (
  <CryptographyProvider>
    <RandomStringDemo />
  </CryptographyProvider>
);

const MultipleRandomDemo = () => {
  const { randomString } = useCryptography();
  const [results, setResults] = useState([]);
  const [count, setCount] = useState(5);
  const [length, setLength] = useState(16);
  const [loading, setLoading] = useState(false);

  const generateMultiple = async () => {
    setLoading(true);
    try {
      const newResults = [];
      for (let i = 0; i < count; i++) {
        const random = await randomString(length);
        newResults.push(random);
      }
      setResults(newResults);
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Batch Random Generation"
      description="Generate multiple random strings at once for bulk operations."
    >
      <Stack spacing={3}>
        <Stack direction="row" spacing={2}>
          <TextField
            label="Number of Strings"
            type="number"
            value={count}
            onChange={(e) => {
              const value = parseInt(e.target.value, 10);
              setCount(Math.min(20, Math.max(1, isNaN(value) ? 1 : value)));
            }}
            inputProps={{ min: 1, max: 20 }}
            sx={{ width: 150 }}
          />
          <TextField
            label="Length per String"
            type="number"
            value={length}
            onChange={(e) => {
              const value = parseInt(e.target.value, 10);
              setLength(Math.min(64, Math.max(8, isNaN(value) ? 8 : value)));
            }}
            inputProps={{ min: 8, max: 64 }}
            sx={{ width: 150 }}
          />
        </Stack>

        <Button
          variant="contained"
          onClick={generateMultiple}
          disabled={loading}
          startIcon={<Refresh />}
        >
          Generate {count} Random Strings
        </Button>

        <OperationStatus loading={loading} />

        {results.length > 0 && (
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Generated {results.length} unique random strings:
            </Typography>
            {results.map((result, index) => (
              <CodeDisplay
                key={index}
                code={result}
                label={`String ${index + 1}`}
              />
            ))}
          </Box>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const BatchGeneration = () => (
  <CryptographyProvider>
    <MultipleRandomDemo />
  </CryptographyProvider>
);