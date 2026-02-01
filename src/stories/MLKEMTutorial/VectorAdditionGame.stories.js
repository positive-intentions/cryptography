/**
 * ML-KEM Tutorial - Vector Addition Game
 * Interactive demonstration of vector addition
 */

import React, { useState } from "react";
import {
  ThemeProvider,
  Container,
  Typography,
  Button,
  TextField,
  Card,
  CardContent,
  Alert,
  Stack,
  Paper,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const VectorAdditionGame = () => {
  const [target, setTarget] = useState({ x: 5, y: 3 });
  const [userVectors, setUserVectors] = useState([
    { label: "Vector A", x: 3, y: 0 },
    { label: "Vector B", x: 0, y: 1 },
    { label: "Vector C", x: 2, y: 2 },
  ]);
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [showSolution, setShowSolution] = useState(false);

  const checkAnswer = () => {
    const sumX = userVectors.reduce((acc, v) => acc + v.x, 0);
    const sumY = userVectors.reduce((acc, v) => acc + v.y, 0);
    const dx = target.x - sumX;
    const dy = target.y - sumY;

    if (dx === 0 && dy === 0) {
      setResult({ sumX, sumY, correct: true });
      setMessage(`Perfect! You reached the target! (${sumX}, ${sumY})`);
    } else {
      setResult({ sumX, sumY, correct: false, dx, dy, target });
      setMessage(`You're at (${sumX}, ${sumY}). Target is (${target.x}, ${target.y})`);
      setShowSolution(true);
    }
  };

  const reset = () => {
    setShowSolution(false);
    setMessage("");
    const newTargetX = Math.floor(Math.random() * 10) - 2;
    const newTargetY = Math.floor(Math.random() * 10) - 2;
    setTarget({ x: Math.max(0, newTargetX), y: Math.max(0, newTargetY) });
  };

  const updateVector = (index, axis, value) => {
    const val = parseInt(value) || 0;
    const newVectors = [...userVectors];
    newVectors[index][axis] = val;
    setUserVectors(newVectors);
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Vector Addition Game
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Combine vectors to reach the target point! Each vector tells you how far to go in each direction.
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Stack spacing={3}>
              {/* Target */}
              <Paper sx={{ p: 2, bgcolor: "success.light" }}>
                <Typography variant="h6">
                  Target Destination: ({target.x}, {target.y})
                </Typography>
                <Typography variant="caption">
                  Try to reach this point by adding your vectors
                </Typography>
              </Paper>

              {/* Vector Builder */}
              <div>
                <Typography variant="subtitle2" gutterBottom>
                  Your Vectors (Add them together)
                </Typography>
                {userVectors.map((vec, i) => (
                  <Stack key={i} direction="row" spacing={2} sx={{ mb: 2, alignItems: "center" }}>
                    <Typography variant="caption" sx={{ minWidth: 80 }}>
                      {vec.label}
                    </Typography>
                    <TextField
                      label="X (East/West)"
                      type="number"
                      value={vec.x}
                      onChange={(e) => updateVector(i, "x", e.target.value)}
                      sx={{ width: 100 }}
                      size="small"
                    />
                    <TextField
                      label="Y (North/South)"
                      type="number"
                      value={vec.y}
                      onChange={(e) => updateVector(i, "y", e.target.value)}
                      sx={{ width: 100 }}
                      size="small"
                    />
                  </Stack>
                ))}
              </div>

              {/* Action Buttons */}
              <Stack direction="row" spacing={2}>
                <Button
                  variant="contained"
                  onClick={checkAnswer}
                  fullWidth
                >
                  Check Answer
                </Button>
                <Button
                  variant="outlined"
                  onClick={reset}
                  fullWidth
                >
                  New Target (Reset)
                </Button>
              </Stack>

              {/* Result */}
              {result && (
                <Alert severity={result.correct ? "success" : "warning"} sx={{ mt: 2 }}>
                  {message}
                </Alert>
              )}

              {/* Solution */}
              {showSolution && !result?.correct && (
                <Paper sx={{ p: 2, mt: 2, bgcolor: "warning.light" }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Solution
                  </Typography>
                  <Typography variant="body2">
                    Current sum: ({result.sumX}, {result.sumY})
                  </Typography>
                  <Typography variant="body2">
                    Need: {result.dx > 0 ? `Go ${result.dx} more East` : result.dx < 0 ? `Go ${Math.abs(result.dx)} more West` : "don't move East-West"}
                  </Typography>
                  <Typography variant="body2">
                    {result.dy > 0 ? `Go ${result.dy} more North` : result.dy < 0 ? `Go ${Math.abs(result.dy)} more South` : "don't move North-South"}
                  </Typography>
                  <Typography variant="caption" sx={{ display: "block", mt: 1 }}>
                    Think of each vector as an arrow. Adding them combines all the "East" and "North" steps!
                  </Typography>
                </Paper>
              )}

              {/* Connection to ML-KEM */}
              <Paper sx={{ p: 2, bgcolor: "info.light" }}>
                <Typography variant="subtitle2" gutterBottom>
                  Connection to ML-KEM
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  ML-KEM uses vector addition to combine 256 different directions at once! We add all polynomial coefficients to compute the final result during key generation and encapsulation.
                </Typography>
              </Paper>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const VectorAddition = () => <VectorAdditionGame />;