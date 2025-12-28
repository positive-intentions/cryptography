import React from "react";
import type { Meta, StoryObj } from "@storybook/react-webpack5";
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Card,
  CardContent,
  Stack,
  Chip,
} from "@mui/material";
import {
  Lock,
  VpnKey,
  Tag,
  Speed,
  Security,
  Shuffle,
} from "@mui/icons-material";

const meta: Meta = {
  title: "Cryptography/Introduction",
  parameters: {
    layout: "centered",
    docs: {
      description: {
        component:
          "Welcome to the Cryptography Module - a comprehensive browser-based cryptography library.",
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

const IntroductionComponent = () => {
  return (
    <Box sx={{ maxWidth: 800, p: 4 }}>
      <Typography variant="h3" component="h1" gutterBottom color="primary">
        🔐 Cryptography Module
      </Typography>

      <Typography variant="h6" color="text.secondary" paragraph>
        A comprehensive browser-based cryptography library built as a
        microfrontend component.
      </Typography>

      <Stack spacing={3} sx={{ mt: 4 }}>
        <Card>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              📋 Overview
            </Typography>
            <Typography variant="body1" paragraph>
              This library provides a thin wrapper around browser cryptography
              APIs, making it easy to perform common cryptographic operations in
              your web applications. It's designed with security, simplicity,
              and modularity in mind.
            </Typography>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              ✨ Features
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <Shuffle />
                </ListItemIcon>
                <ListItemText
                  primary="Random Generation"
                  secondary="Cryptographically secure random strings and deterministic generation with seeds"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Tag />
                </ListItemIcon>
                <ListItemText
                  primary="Hashing Functions"
                  secondary="SHA-256, SHA-512, and SHA3-512 algorithms for data integrity"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <VpnKey />
                </ListItemIcon>
                <ListItemText
                  primary="Asymmetric Encryption (RSA)"
                  secondary="4096-bit RSA-OAEP encryption with key pair generation"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Lock />
                </ListItemIcon>
                <ListItemText
                  primary="Symmetric Encryption (AES)"
                  secondary="AES-GCM encryption for fast, secure data protection"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Speed />
                </ListItemIcon>
                <ListItemText
                  primary="Performance Benchmarks"
                  secondary="Built-in performance testing and algorithm comparison tools"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Security />
                </ListItemIcon>
                <ListItemText
                  primary="Module Federation Ready"
                  secondary="Seamless integration with other microfrontends in the ecosystem"
                />
              </ListItem>
            </List>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              🚀 Getting Started
            </Typography>
            <Typography variant="body1" paragraph>
              Explore the different categories in the sidebar to see interactive
              demos and examples:
            </Typography>
            <Stack
              direction="row"
              spacing={1}
              sx={{ flexWrap: "wrap", gap: 1 }}
            >
              <Chip
                label="Random Generation"
                color="primary"
                variant="outlined"
              />
              <Chip label="Hashing" color="secondary" variant="outlined" />
              <Chip label="RSA Encryption" color="success" variant="outlined" />
              <Chip label="AES Encryption" color="info" variant="outlined" />
              <Chip label="Use Cases" color="warning" variant="outlined" />
              <Chip label="Performance" color="error" variant="outlined" />
            </Stack>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              🔧 Technical Details
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Built with React 18, Material-UI, Storybook 9, and Module
              Federation. Uses native Web Crypto APIs for maximum performance
              and security.
            </Typography>
          </CardContent>
        </Card>
      </Stack>
    </Box>
  );
};

export const Welcome: Story = {
  render: () => <IntroductionComponent />,
};
