/**
 * ML-KEM Tutorial - Matrix Vector Multiplication Demo
 * Visual demonstration of matrix-vector multiplication
 */

import React, { useState } from "react";
import {
  ThemeProvider,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Alert,
  Stack,
  Paper,
  TextField,
  Grid,
  Box,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const MatrixTransformer = () => {
  const [matrix, setMatrix] = useState({
    rows: 3,
    cols: 3,
    values: [
      [1, 2, 3],
      [4, 5, 6],
      [7, 8, 9],
    ]
  });
  const [vector, setVector] = useState([1, 2, 3]);
  const [result, setResult] = useState(null);
  const [expanded, setExpanded] = useState(false);

  const multiply = () => {
    const resultVec = [];
    for (let i = 0; i < matrix.rows; i++) {
      let sum = 0;
      for (let j = 0; j < matrix.cols; j++) {
        sum += matrix.values[i][j] * (vector[j] || 0);
      }
      resultVec.push(sum);
    }
    setResult(resultVec);
    setExpanded(true);
  };

  const updateMatrixValue = (row, col, val) => {
    const num = parseInt(val) || 0;
    const newMatrix = { ...matrix };
    newMatrix.values[row][col] = num;
    setMatrix(newMatrix);
    setResult(null);
    setExpanded(false);
  };

  const updateVector = (index, val) => {
    const num = parseInt(val) || 0;
    const newVector = [...vector];
    newVector[index] = num;
    setVector(newVector);
    setResult(null);
    setExpanded(false);
  };

  const generateRandom = () => {
    const rows = 3;
    const cols = 3;
    const values = [];
    for (let i = 0; i < rows; i++) {
      const row = [];
      for (let j = 0; j < cols; j++) {
        row.push(Math.floor(Math.random() * 10));
      }
      values.push(row);
    }
    const randomVector = [];
    for (let i = 0; i < 3; i++) {
      randomVector.push(Math.floor(Math.random() * 5));
    }
    setMatrix({ rows, cols, values });
    setVector(randomVector);
    setResult(null);
    setExpanded(false);
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Matrix-Vector Multiplication
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          See how matrices multiply vectors. This is how ML-KEM's key generation computes the public key!
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Stack spacing={3}>
              {/* Controls */}
              <Stack direction="row" spacing={2}>
                <Button
                  variant="contained"
                  onClick={multiply}
                  disabled={expanded}
                >
                  Multiply
                </Button>
                <Button
                  variant="outlined"
                  onClick={generateRandom}
                >
                  Random Example
                </Button>
              </Stack>

              {/* Matrix Display */}
              <Paper sx={{ p: 2, bgcolor: "grey.50" }}>
                <Typography variant="subtitle2" gutterBottom>
                  Matrix A
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  {matrix.values.map((row, i) => (
                    <Box key={i} sx={{ display: "flex", gap: 1 }}>
                      {row.map((val, j) => (
                        <Box key={j}>
                          <TextField
                            size="small"
                            value={val}
                            onChange={(e) => updateMatrixValue(i, j, e.target.value)}
                            type="number"
                            sx={{ width: 60 }}
                          />
                        </Box>
                      ))}
                    </Box>
                  ))}
                </Box>
              </Paper>

              {/* Vector Display */}
              <Paper sx={{ p: 2, bgcolor: "grey.100" }}>
                <Typography variant="subtitle2" gutterBottom>
                  Vector v (Secret)
                </Typography>
                <Box sx={{ display: "flex", gap: 1 }}>
                  {vector.map((val, i) => (
                    <TextField
                      key={i}
                      label={`v${i + 1}`}
                      size="small"
                      value={val}
                      onChange={(e) => updateVector(i, e.target.value)}
                      type="number"
                      sx={{ width: 70 }}
                    />
                  ))}
                </Box>
              </Paper>

              {/* Result */}
              {expanded && result && (
                <Paper sx={{ p: 2, bgcolor: "success.light" }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Result: A × v
                  </Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: "1.2rem" }}>
                    ({result.join(", ")})
                  </Box>
                  <Typography variant="caption" sx={{ display: "block", mt: 1 }}>
                    Multiply each row by the vector's elements, then sum
                  </Typography>
                </Paper>
              )}

              {/* Explanation */}
              {expanded && result && (
                <Paper sx={{ p: 2, bgcolor: "info.light" }}>
                  <Typography variant="subtitle2" gutterBottom>
                    How It Works
                  </Typography>
                  {matrix.values.map((row, i) => (
                    <Typography key={i} variant="body2">
                      Row {i + 1}: {row.map((val, j) => `${val} × v${j + 1}${j < row.length - 1 ? " + " : " = "}`)}{result[i]}
                    </Typography>
                  ))}
                </Paper>
              )}

              {/* ML-KEM Connection */}
              <Paper sx={{ p: 2, bgcolor: "warning.light" }}>
                <Typography variant="subtitle2" gutterBottom>
                  ML-KEM Key Generation
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  In ML-KEM, this exact multiplication happens: ${"\\mathbf{t} = \\mathbf{A}\\mathbf{s} + \\mathbf{e}"}$.
                  The matrix A (public) times secret s plus error e gives us the public key t!
                </Typography>
              </Paper>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const MatrixTranspose = () => <MatrixTransformer />;