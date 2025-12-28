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
  Box,
  Typography,
  Stack,
  Card,
  CardContent,
  CardHeader,
  Grid,
  Paper,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Alert,
  Slider,
  Speed,
  Timer,
  SwapHoriz as Compare,
  Assessment,
  TrendingUp,
} from "ui";

export default {
  title: "Cryptography/Performance/Benchmarks",
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component:
          "Performance benchmarks comparing different cryptographic operations and algorithms.",
      },
    },
  },
};

const HashingBenchmarkDemo = () => {
  const { sha256Hash, sha512Hash, sha3_512Hash } = useCryptography();
  const [dataSize, setDataSize] = useState(1000);
  const [iterations, setIterations] = useState(100);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const generateTestData = (size) => {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < size; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const runBenchmark = async () => {
    setLoading(true);
    setProgress(0);
    setResults([]);

    const testData = generateTestData(dataSize);
    const algorithms = [
      { name: "SHA-256", func: sha256Hash, color: "primary" },
      { name: "SHA-512", func: sha512Hash, color: "secondary" },
      { name: "SHA3-512", func: sha3_512Hash, color: "success" },
    ];

    const benchmarkResults = [];

    for (let i = 0; i < algorithms.length; i++) {
      const algo = algorithms[i];
      const times = [];

      for (let j = 0; j < iterations; j++) {
        const start = performance.now();
        await algo.func(testData);
        const end = performance.now();
        times.push(end - start);

        setProgress(
          ((i * iterations + j + 1) / (algorithms.length * iterations)) * 100,
        );
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      const throughput = ((dataSize / avgTime) * 1000).toFixed(0);

      benchmarkResults.push({
        algorithm: algo.name,
        color: algo.color,
        avgTime: avgTime.toFixed(2),
        minTime: minTime.toFixed(2),
        maxTime: maxTime.toFixed(2),
        throughput: throughput,
      });
    }

    setResults(benchmarkResults);
    setLoading(false);
  };

  return (
    <CryptoDemo
      title="Hashing Performance Benchmark"
      description="Compare the performance of different hash algorithms across multiple iterations."
    >
      <Stack spacing={3}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Box>
              <Typography gutterBottom>
                Data Size: {dataSize.toLocaleString()} characters
              </Typography>
              <Slider
                value={dataSize}
                onChange={(e, val) => setDataSize(val)}
                min={100}
                max={10000}
                step={100}
                marks={[
                  { value: 100, label: "100" },
                  { value: 1000, label: "1K" },
                  { value: 5000, label: "5K" },
                  { value: 10000, label: "10K" },
                ]}
                valueLabelDisplay="auto"
              />
            </Box>
          </Grid>

          <Grid item xs={12} md={6}>
            <Box>
              <Typography gutterBottom>Iterations: {iterations}</Typography>
              <Slider
                value={iterations}
                onChange={(e, val) => setIterations(val)}
                min={10}
                max={500}
                step={10}
                marks={[
                  { value: 10, label: "10" },
                  { value: 100, label: "100" },
                  { value: 250, label: "250" },
                  { value: 500, label: "500" },
                ]}
                valueLabelDisplay="auto"
              />
            </Box>
          </Grid>
        </Grid>

        <Button
          variant="contained"
          onClick={runBenchmark}
          disabled={loading}
          startIcon={<Speed />}
          size="large"
        >
          Run Benchmark ({iterations} iterations each)
        </Button>

        {loading && (
          <Box>
            <LinearProgress
              variant="determinate"
              value={progress}
              sx={{ mb: 1 }}
            />
            <Typography variant="body2" color="text.secondary" align="center">
              Progress: {progress.toFixed(1)}%
            </Typography>
          </Box>
        )}

        {results.length > 0 && (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Algorithm</TableCell>
                  <TableCell align="right">Avg Time (ms)</TableCell>
                  <TableCell align="right">Min Time (ms)</TableCell>
                  <TableCell align="right">Max Time (ms)</TableCell>
                  <TableCell align="right">Throughput (chars/sec)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((result) => (
                  <TableRow key={result.algorithm}>
                    <TableCell component="th" scope="row">
                      <Chip
                        label={result.algorithm}
                        color={result.color}
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell align="right">{result.avgTime}</TableCell>
                    <TableCell align="right">{result.minTime}</TableCell>
                    <TableCell align="right">{result.maxTime}</TableCell>
                    <TableCell align="right">{result.throughput}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        <OperationStatus loading={loading} />
      </Stack>
    </CryptoDemo>
  );
};

export const HashingBenchmark = () => (
  <CryptographyProvider>
    <HashingBenchmarkDemo />
  </CryptographyProvider>
);

const EncryptionBenchmarkDemo = () => {
  const {
    generateKeyPair,
    generateSymmetricKey,
    deserializePublicKey,
    deserializeSymmetricKey,
    encrypt,
    encryptWithSymmetricKey,
  } = useCryptography();

  const [rsaKeyPair, setRsaKeyPair] = useState(null);
  const [aesKey, setAesKey] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const initializeKeys = async () => {
    setLoading(true);
    try {
      const [rsa, aes] = await Promise.all([
        generateKeyPair(),
        generateSymmetricKey(),
      ]);
      setRsaKeyPair(rsa);
      setAesKey(aes);
    } catch (error) {
      setLoading(false);
    }
  };

  const runEncryptionBenchmark = async () => {
    if (!rsaKeyPair || !aesKey) return;

    setLoading(true);
    setProgress(0);

    const testSizes = [100, 200, 400]; // RSA has size limits
    const iterations = 50;
    const benchmarkResults = [];

    try {
      const publicKey = await deserializePublicKey(rsaKeyPair.publicKey);
      const symmetricKey = await deserializeSymmetricKey(aesKey);

      for (let size of testSizes) {
        const testData = "A".repeat(size);

        // RSA Benchmark
        const rsaTimes = [];
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          try {
            await encrypt(testData, publicKey);
            const end = performance.now();
            rsaTimes.push(end - start);
          } catch (error) {
            // RSA failed - data too large
            break;
          }
          setProgress(
            (rsaTimes.length / (testSizes.length * iterations * 2)) * 100,
          );
        }

        // AES Benchmark
        const aesTimes = [];
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          await encryptWithSymmetricKey(testData, symmetricKey);
          const end = performance.now();
          aesTimes.push(end - start);
          setProgress(
            ((testSizes.indexOf(size) * iterations * 2 +
              rsaTimes.length +
              aesTimes.length) /
              (testSizes.length * iterations * 2)) *
              100,
          );
        }

        benchmarkResults.push({
          size,
          rsa: {
            success: rsaTimes.length > 0,
            avgTime:
              rsaTimes.length > 0
                ? (
                    rsaTimes.reduce((a, b) => a + b, 0) / rsaTimes.length
                  ).toFixed(2)
                : "N/A",
            throughput:
              rsaTimes.length > 0
                ? (
                    (size /
                      (rsaTimes.reduce((a, b) => a + b, 0) / rsaTimes.length)) *
                    1000
                  ).toFixed(0)
                : "N/A",
          },
          aes: {
            success: aesTimes.length > 0,
            avgTime:
              aesTimes.length > 0
                ? (
                    aesTimes.reduce((a, b) => a + b, 0) / aesTimes.length
                  ).toFixed(2)
                : "N/A",
            throughput:
              aesTimes.length > 0
                ? (
                    (size /
                      (aesTimes.reduce((a, b) => a + b, 0) / aesTimes.length)) *
                    1000
                  ).toFixed(0)
                : "N/A",
          },
        });
      }

      setResults(benchmarkResults);
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="RSA vs AES Encryption Benchmark"
      description="Compare RSA and AES encryption performance with different data sizes."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          This benchmark demonstrates why RSA is typically used only for small
          data or key exchange, while AES is used for bulk encryption.
        </Alert>

        {!rsaKeyPair || !aesKey ? (
          <Button
            variant="contained"
            onClick={initializeKeys}
            disabled={loading}
            startIcon={<Timer />}
            size="large"
          >
            Initialize Keys
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={runEncryptionBenchmark}
            disabled={loading}
            startIcon={<Compare />}
            size="large"
          >
            Run Encryption Benchmark
          </Button>
        )}

        {loading && (
          <Box>
            <LinearProgress
              variant="determinate"
              value={progress}
              sx={{ mb: 1 }}
            />
            <Typography variant="body2" color="text.secondary" align="center">
              Progress: {progress.toFixed(1)}%
            </Typography>
          </Box>
        )}

        {results && (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Data Size (bytes)</TableCell>
                  <TableCell align="center" colSpan={2}>
                    RSA-OAEP
                  </TableCell>
                  <TableCell align="center" colSpan={2}>
                    AES-GCM
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell></TableCell>
                  <TableCell align="right">Avg Time (ms)</TableCell>
                  <TableCell align="right">Throughput (bytes/sec)</TableCell>
                  <TableCell align="right">Avg Time (ms)</TableCell>
                  <TableCell align="right">Throughput (bytes/sec)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((result) => (
                  <TableRow key={result.size}>
                    <TableCell component="th" scope="row">
                      {result.size}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{
                        color: result.rsa.success
                          ? "text.primary"
                          : "error.main",
                        fontStyle: result.rsa.success ? "normal" : "italic",
                      }}
                    >
                      {result.rsa.avgTime}
                    </TableCell>
                    <TableCell
                      align="right"
                      sx={{
                        color: result.rsa.success
                          ? "text.primary"
                          : "error.main",
                        fontStyle: result.rsa.success ? "normal" : "italic",
                      }}
                    >
                      {result.rsa.throughput}
                    </TableCell>
                    <TableCell align="right">{result.aes.avgTime}</TableCell>
                    <TableCell align="right">{result.aes.throughput}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        <OperationStatus loading={loading} />
      </Stack>
    </CryptoDemo>
  );
};

export const EncryptionBenchmark = () => (
  <CryptographyProvider>
    <EncryptionBenchmarkDemo />
  </CryptographyProvider>
);

const KeyGenerationBenchmarkDemo = () => {
  const { generateKeyPair, generateSymmetricKey } = useCryptography();
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const runKeyGenBenchmark = async () => {
    setLoading(true);
    setProgress(0);
    setResults([]);

    const iterations = 5; // Fewer iterations for key generation
    const benchmarkResults = [];

    try {
      // RSA Key Generation Benchmark
      const rsaTimes = [];
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await generateKeyPair();
        const end = performance.now();
        rsaTimes.push(end - start);
        setProgress(((i + 1) / (iterations * 2)) * 100);
      }

      // AES Key Generation Benchmark
      const aesTimes = [];
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await generateSymmetricKey();
        const end = performance.now();
        aesTimes.push(end - start);
        setProgress(((iterations + i + 1) / (iterations * 2)) * 100);
      }

      benchmarkResults.push({
        algorithm: "RSA-4096",
        color: "primary",
        avgTime: (
          rsaTimes.reduce((a, b) => a + b, 0) / rsaTimes.length
        ).toFixed(2),
        minTime: Math.min(...rsaTimes).toFixed(2),
        maxTime: Math.max(...rsaTimes).toFixed(2),
        operations: iterations,
        type: "Key Pair Generation",
      });

      benchmarkResults.push({
        algorithm: "AES-256",
        color: "secondary",
        avgTime: (
          aesTimes.reduce((a, b) => a + b, 0) / aesTimes.length
        ).toFixed(2),
        minTime: Math.min(...aesTimes).toFixed(2),
        maxTime: Math.max(...aesTimes).toFixed(2),
        operations: iterations,
        type: "Symmetric Key Generation",
      });

      setResults(benchmarkResults);
    } catch (error) {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Key Generation Performance"
      description="Compare the time required to generate different types of cryptographic keys."
    >
      <Stack spacing={3}>
        <Alert severity="warning">
          RSA key generation is computationally expensive and may take several
          seconds. In production, keys should be generated once and reused.
        </Alert>

        <Button
          variant="contained"
          onClick={runKeyGenBenchmark}
          disabled={loading}
          startIcon={<Assessment />}
          size="large"
        >
          Run Key Generation Benchmark
        </Button>

        {loading && (
          <Box>
            <LinearProgress
              variant="determinate"
              value={progress}
              sx={{ mb: 1 }}
            />
            <Typography variant="body2" color="text.secondary" align="center">
              Progress: {progress.toFixed(1)}%
            </Typography>
          </Box>
        )}

        {results.length > 0 && (
          <Grid container spacing={2}>
            {results.map((result) => (
              <Grid item xs={12} md={6} key={result.algorithm}>
                <Card>
                  <CardHeader
                    title={result.algorithm}
                    subheader={result.type}
                    action={
                      <Chip
                        label={`${result.operations} iterations`}
                        color={result.color}
                        size="small"
                      />
                    }
                  />
                  <CardContent>
                    <Stack spacing={2}>
                      <Box display="flex" justifyContent="space-between">
                        <Typography variant="body2" color="text.secondary">
                          Average Time:
                        </Typography>
                        <Typography variant="body2" fontWeight="bold">
                          {result.avgTime}ms
                        </Typography>
                      </Box>

                      <Box display="flex" justifyContent="space-between">
                        <Typography variant="body2" color="text.secondary">
                          Fastest:
                        </Typography>
                        <Typography variant="body2" color="success.main">
                          {result.minTime}ms
                        </Typography>
                      </Box>

                      <Box display="flex" justifyContent="space-between">
                        <Typography variant="body2" color="text.secondary">
                          Slowest:
                        </Typography>
                        <Typography variant="body2" color="error.main">
                          {result.maxTime}ms
                        </Typography>
                      </Box>
                    </Stack>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        <OperationStatus loading={loading} />

        <Box>
          <Typography variant="h6" gutterBottom>
            Key Generation Best Practices
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography
                  variant="subtitle2"
                  gutterBottom
                  color="success.main"
                >
                  ✅ Do
                </Typography>
                <Typography
                  component="ul"
                  variant="body2"
                  color="text.secondary"
                >
                  <li>Generate keys once and store securely</li>
                  <li>Use appropriate key sizes for your security needs</li>
                  <li>Generate keys on secure, trusted devices</li>
                  <li>Consider using hardware security modules</li>
                </Typography>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom color="error.main">
                  ❌ Don't
                </Typography>
                <Typography
                  component="ul"
                  variant="body2"
                  color="text.secondary"
                >
                  <li>Generate keys repeatedly for the same purpose</li>
                  <li>Generate keys on untrusted or compromised systems</li>
                  <li>Use weak entropy sources</li>
                  <li>Generate keys synchronously in UI threads</li>
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Box>
      </Stack>
    </CryptoDemo>
  );
};

export const KeyGenerationBenchmark = () => (
  <CryptographyProvider>
    <KeyGenerationBenchmarkDemo />
  </CryptographyProvider>
);
