import React from "react";
import type { Meta, StoryObj } from "@storybook/react";
import { CryptographyProvider, useCryptography } from "./components/Cryptography.tsx";
import { Box, Typography, Button, Stack } from "@mui/material";

const meta: Meta<typeof CryptographyProvider> = {
  title: "Cryptography/Core/Provider",
  component: CryptographyProvider,
  parameters: {
    layout: "centered",
    docs: {
      description: {
        component: 'Core cryptography provider that enables all cryptographic functions throughout the application.',
      },
    },
  },
  tags: ["autodocs"],
  argTypes: {
    entropy: {
      control: "text",
      description: "Optional entropy to seed deterministic operations",
    },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

const BasicDemo = ({ entropy }) => {
  const crypto = useCryptography();
  const [result, setResult] = React.useState("");
  
  const testBasicFunction = async () => {
    try {
      const hash = await crypto.sha256Hash("Hello, Cryptography!");
      setResult(hash);
    } catch (error) {
      setResult(`Error: ${error.message}`);
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 500 }}>
      <Typography variant="h6" gutterBottom>
        Cryptography Provider Demo
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Click the button below to test basic cryptographic functionality.
      </Typography>
      <Stack spacing={2}>
        <Button variant="contained" onClick={testBasicFunction}>
          Test SHA-256 Hash
        </Button>
        {result && (
          <Box sx={{ p: 2, bgcolor: 'background.paper', borderRadius: 1 }}>
            <Typography variant="caption" color="text.secondary">
              Result:
            </Typography>
            <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
              {result}
            </Typography>
          </Box>
        )}
      </Stack>
    </Box>
  );
};

export const Basic: Story = {
  args: {
    entropy: "",
  },
  render: (args) => (
    <CryptographyProvider entropy={args.entropy}>
      <BasicDemo entropy={args.entropy} />
    </CryptographyProvider>
  ),
};

export const WithEntropy: Story = {
  args: {
    entropy: "test-seed-123",
  },
  render: (args) => (
    <CryptographyProvider entropy={args.entropy}>
      <BasicDemo entropy={args.entropy} />
    </CryptographyProvider>
  ),
};
