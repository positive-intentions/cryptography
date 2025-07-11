import React, { useState } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from '../components/shared';
import { 
  Button, 
  TextField, 
  Box, 
  Typography,
  Stack,
  Alert,
  Chip,
  Paper,
  Grid
} from '@mui/material';
import { Autorenew, Science } from '@mui/icons-material';

export default {
  title: 'Cryptography/Random Generation/Deterministic Random',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'Generate deterministic "random" values using Chance.js with a seed. Same seed always produces same output.',
      },
    },
  },
};

const DeterministicDemo = () => {
  const crypto = useCryptography();
  const [seed, setSeed] = useState('my-test-seed');
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState(false);

  const generateDeterministic = async () => {
    setLoading(true);
    try {
      // Get the Chance instance with seed
      const chance = crypto.chance(seed);
      
      // Generate various types of deterministic "random" data
      const newResults = {
        guid: chance.guid(),
        integer: chance.integer({ min: 1, max: 100 }),
        floating: chance.floating({ min: 0, max: 1, fixed: 4 }),
        string: chance.string({ length: 10 }),
        bool: chance.bool(),
        character: chance.character(),
        word: chance.word(),
        sentence: chance.sentence({ words: 5 }),
        name: chance.name(),
        email: chance.email(),
        ip: chance.ip(),
        color: chance.color({ format: 'hex' }),
        date: chance.date({ year: 2024 }).toDateString(),
      };
      
      setResults(newResults);
    } catch (error) {
      console.error('Error generating deterministic values:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Deterministic Random Generation"
      description="Using Chance.js with a seed to generate reproducible 'random' values. Perfect for testing and simulations."
    >
      <Alert severity="info" sx={{ mb: 3 }}>
        Deterministic generation means the same seed will always produce the same sequence of values. 
        This is NOT cryptographically secure and should only be used for testing or non-security purposes.
      </Alert>

      <Stack spacing={3}>
        <TextField
          label="Seed Value"
          value={seed}
          onChange={(e) => setSeed(e.target.value)}
          fullWidth
          helperText="Same seed = same output every time"
          variant="outlined"
        />

        <Button
          variant="contained"
          onClick={generateDeterministic}
          disabled={loading}
          startIcon={<Science />}
          size="large"
        >
          Generate Deterministic Values
        </Button>

        <OperationStatus loading={loading} />

        {Object.keys(results).length > 0 && (
          <Box>
            <Typography variant="h6" gutterBottom sx={{ mb: 2 }}>
              Generated Values (Seed: "{seed}")
            </Typography>
            
            <Grid container spacing={2}>
              {Object.entries(results).map(([key, value]) => (
                <Grid item xs={12} sm={6} key={key}>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Typography variant="caption" color="text.secondary">
                      {key.charAt(0).toUpperCase() + key.slice(1)}
                    </Typography>
                    <Typography variant="body1" sx={{ fontFamily: 'monospace', mt: 0.5 }}>
                      {String(value)}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        <Box sx={{ mt: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Try changing the seed and regenerating. Then change it back to see the same values return!
          </Typography>
        </Box>
      </Stack>
    </CryptoDemo>
  );
};

export const Default = () => (
  <CryptographyProvider>
    <DeterministicDemo />
  </CryptographyProvider>
);

const ComparisonDemo = () => {
  const crypto = useCryptography();
  const [seed1, setSeed1] = useState('seed-A');
  const [seed2, setSeed2] = useState('seed-B');
  const [comparison, setComparison] = useState({ set1: [], set2: [] });
  const [loading, setLoading] = useState(false);

  const generateComparison = async () => {
    setLoading(true);
    try {
      const chance1 = crypto.chance(seed1);
      const chance2 = crypto.chance(seed2);
      
      const set1 = [];
      const set2 = [];
      
      for (let i = 0; i < 5; i++) {
        set1.push(chance1.integer({ min: 1, max: 100 }));
        set2.push(chance2.integer({ min: 1, max: 100 }));
      }
      
      setComparison({ set1, set2 });
    } catch (error) {
      console.error('Error in comparison:', error);
    } finally {
      setLoading(false);
    }
  };

  const areSeedsEqual = seed1 === seed2;

  return (
    <CryptoDemo
      title="Seed Comparison"
      description="Compare outputs from different seeds to understand deterministic behavior."
    >
      <Stack spacing={3}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField
              label="Seed 1"
              value={seed1}
              onChange={(e) => setSeed1(e.target.value)}
              fullWidth
              variant="outlined"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField
              label="Seed 2"
              value={seed2}
              onChange={(e) => setSeed2(e.target.value)}
              fullWidth
              variant="outlined"
            />
          </Grid>
        </Grid>

        {areSeedsEqual && (
          <Alert severity="warning">
            Seeds are identical - outputs will be the same!
          </Alert>
        )}

        <Button
          variant="contained"
          onClick={generateComparison}
          disabled={loading}
          startIcon={<Autorenew />}
        >
          Generate & Compare
        </Button>

        <OperationStatus loading={loading} />

        {comparison.set1.length > 0 && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Seed 1: "{seed1}"
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  {comparison.set1.map((val, idx) => (
                    <Chip 
                      key={idx} 
                      label={val} 
                      color="primary" 
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Seed 2: "{seed2}"
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  {comparison.set2.map((val, idx) => (
                    <Chip 
                      key={idx} 
                      label={val} 
                      color={val === comparison.set1[idx] ? "primary" : "secondary"} 
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Paper>
            </Grid>
          </Grid>
        )}

        <Box sx={{ mt: 3 }}>
          <Typography variant="h6" gutterBottom>
            Use Cases for Deterministic Generation
          </Typography>
          <Typography component="ul" variant="body2" color="text.secondary">
            <li>Unit testing with predictable data</li>
            <li>Generating consistent demo/sample data</li>
            <li>Debugging with reproducible scenarios</li>
            <li>Creating deterministic simulations</li>
            <li>Generating placeholder data for development</li>
          </Typography>
          
          <Alert severity="warning" sx={{ mt: 2 }}>
            <strong>Security Note:</strong> Never use deterministic generation for security-critical 
            random values like passwords, tokens, or cryptographic keys. Use the cryptographically 
            secure randomString() function instead.
          </Alert>
        </Box>
      </Stack>
    </CryptoDemo>
  );
};

export const SeedComparison = () => (
  <CryptographyProvider>
    <ComparisonDemo />
  </CryptographyProvider>
);