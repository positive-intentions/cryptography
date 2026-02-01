/**
 * ML-KEM Tutorial - Clock Wrap Demo
 * Interactive demonstration of modular arithmetic (clock math)
 */

import React, { useState, useEffect } from "react";
import {
  ThemeProvider,
  Container,
  Typography,
  Button,
  TextField,
  Box,
  Card,
  CardContent,
  Slider,
  Alert,
  Stack,
  Divider,
} from "ui";

export default {
  title: "Cascading Cipher/ML-KEM Tutorial",
  parameters: {
    layout: "fullscreen",
  },
};

const ClockWrapDemo = () => {
  const [modulus, setModulus] = useState(12);
  const [input, setInput] = useState(15);
  const [result, setResult] = useState(null);
  const [steps, setSteps] = useState([]);
  const [showAnswer, setShowAnswer] = useState(false);

  useEffect(() => {
    const mod = parseInt(modulus);
    const num = parseInt(input);

    if (isNaN(mod) || isNaN(num) || mod < 2) {
      setResult(null);
      setShowAnswer(false);
      return;
    }

    const newSteps = [];
    newSteps.push({ type: "info", text: `Calculating: ${num} mod ${mod}` });

    const fullRotations = Math.floor(num / mod);
    const remainder = num % mod;
    newSteps.push({ type: "info", text: `Full rotations around the clock: ${fullRotations}` });
    newSteps.push({ type: "info", text: `Where we land: ${remainder} o'clock` });

    const clockNumbers = [];
    for (let i = 0; i < mod; i++) {
      clockNumbers.push(i);
    }
    const startAngle = 90 - (360 / mod) * 0.5;
    const anglePerHour = 360 / mod;

    newSteps.push({
      type: "success",
      text: `Result: ${num} mod ${mod} = ${remainder}`,
    });
    newSteps.push({
      type: "visual",
      text: `Think of it like this: We go around ${fullRotations} full time(s) and land at ${remainder}`,
    });

    setResult({ fullRotations, remainder, clockNumbers, startAngle, anglePerHour });
    setShowAnswer(true);
    setSteps(newSteps);
  }, [modulus, input]);

  const reset = () => {
    setInput(15);
    setResult(null);
    setSteps([]);
    setShowAnswer(false);
  };

  return (
    <ThemeProvider>
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Typography variant="h4" gutterBottom>
          Clock Math: Modular Arithmetic
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Like numbers wrapping around on a clock face. What time is it 15 hours after 3 o'clock?
        </Typography>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Stack spacing={3}>
              <div>
                <Typography variant="subtitle2" gutterBottom>
                  Clock Size (Modulus)
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  How many numbers on the clock? (e.g., 12 for a clock, 7 for days of week)
                </Typography>
                <Slider
                  value={modulus}
                  onChange={(e, val) => setModulus(val)}
                  min={2}
                  max={24}
                  valueLabelDisplay="auto"
                  sx={{ mt: 2 }}
                />
              </div>

              <div>
                <TextField
                  fullWidth
                  label="Number to Wrap"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  type="number"
                  helperText="How many hours will pass?"
                />
              </div>

              {result && (
                <Box sx={{ mt: 3 }}>
                  <Divider sx={{ mb: 2 }} />

                  <Typography variant="h6" gutterBottom>
                    Clock Visualization
                  </Typography>

                  <Box
                    sx={{
                      display: "flex",
                      justifyContent: "center",
                      my: 3,
                    }}
                  >
                    <svg width="200" height="200">
                      {/* Outer circle */}
                      <circle
                        cx="100"
                        cy="100"
                        r="90"
                        fill="none"
                        stroke="black"
                        strokeWidth="2"
                      />

                      {/* Clock numbers */}
                      {result.clockNumbers.map((num) => {
                        const totalPerNumber = result.anglePerHour;
                        const angle = result.startAngle - num * totalPerNumber;
                        const rad = (angle * Math.PI) / 180;
                        const x = 100 + 70 * Math.cos(rad);
                        const y = 100 - 70 * Math.sin(rad);

                        const isTarget = num === result.remainder;

                        return (
                          <g key={num}>
                            <circle
                              cx={x}
                              cy={y}
                              r={isTarget ? 15 : 12}
                              fill={isTarget ? "red" : "white"}
                              stroke="black"
                              strokeWidth={isTarget ? 3 : 1}
                            />
                            <text
                              x={x}
                              y={y}
                              textAnchor="middle"
                              dominantBaseline="middle"
                              fontSize={isTarget ? 14 : 11}
                              fontWeight={isTarget ? "bold" : "normal"}
                            >
                              {num}
                            </text>
                          </g>
                        );
                      })}

                      {/* Hand pointing to result */}
                      {result.clockNumbers.map((num) => {
                        if (num === result.remainder) {
                          const totalPerNumber = result.anglePerHour;
                          const angle = result.startAngle - num * totalPerNumber;
                          const rad = (angle * Math.PI) / 180;

                          return (
                            <line
                              key="hand"
                              x1="100"
                              y1="100"
                              x2={100 + 55 * Math.cos(rad)}
                              y2={100 - 55 * Math.sin(rad)}
                              stroke="black"
                              strokeWidth="3"
                            />
                          );
                        }
                        return null;
                      })}
                    </svg>
                  </Box>

                  {/* Steps explanation */}
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Calculation Steps
                    </Typography>
                    {steps.map((step, i) => (
                      <Alert
                        key={i}
                        severity={step.type === "error" ? "error" : step.type === "success" ? "success" : "info"}
                        sx={{ mb: 1 }}
                      >
                        {step.text}
                      </Alert>
                    ))}
                  </Box>

                  {/* ML-KEM connection */}
                  <Box sx={{ mt: 3, p: 2, bgcolor: "grey.100", borderRadius: 1 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Connection to ML-KEM
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      In ML-KEM, polynomials wrap around like a clock:
                      coefficients go from 0 to 3328, then back to 0. This is modular arithmetic.
                    </Typography>
                  </Box>
                </Box>
              )}
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </ThemeProvider>
  );
};

export const ClockWrap = () => <ClockWrapDemo />;