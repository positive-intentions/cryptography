import React, { useState } from 'react';
import { Box, Typography, IconButton, Tooltip, Snackbar, Alert } from '@mui/material';
import { ContentCopy, Visibility, VisibilityOff } from '@mui/icons-material';
import { styled } from '@mui/material/styles';

const CodeContainer = styled(Box)(({ theme }) => ({
  backgroundColor: theme.palette.mode === 'dark' ? '#0a0a0a' : '#f5f5f5',
  border: `1px solid ${theme.palette.divider}`,
  borderRadius: theme.shape.borderRadius,
  padding: theme.spacing(2),
  position: 'relative',
  fontFamily: 'Consolas, Monaco, "Courier New", monospace',
  fontSize: '0.875rem',
  wordBreak: 'break-all',
  overflowWrap: 'break-word',
}));

const ActionButtons = styled(Box)(({ theme }) => ({
  position: 'absolute',
  top: theme.spacing(1),
  right: theme.spacing(1),
  display: 'flex',
  gap: theme.spacing(0.5),
}));

export const CodeDisplay = ({ 
  code, 
  label, 
  secret = false, 
  language = 'text',
  maxHeight = 'auto' 
}) => {
  const [showSecret, setShowSecret] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const displayCode = secret && !showSecret 
    ? '•'.repeat(Math.min(code.length, 50)) + (code.length > 50 ? '...' : '')
    : code;

  return (
    <Box sx={{ mb: 2 }}>
      {label && (
        <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>
          {label}
        </Typography>
      )}
      <CodeContainer sx={{ maxHeight, overflow: maxHeight !== 'auto' ? 'auto' : 'visible' }}>
        <ActionButtons>
          {secret && (
            <Tooltip title={showSecret ? "Hide" : "Show"}>
              <IconButton 
                size="small" 
                onClick={() => setShowSecret(!showSecret)}
                sx={{ color: 'text.secondary' }}
              >
                {showSecret ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Copy to clipboard">
            <IconButton 
              size="small" 
              onClick={handleCopy}
              sx={{ color: 'text.secondary' }}
            >
              <ContentCopy fontSize="small" />
            </IconButton>
          </Tooltip>
        </ActionButtons>
        <Typography
          component="pre"
          sx={{
            margin: 0,
            color: 'text.primary',
            pr: 8,
          }}
        >
          {displayCode}
        </Typography>
      </CodeContainer>
      <Snackbar
        open={copied}
        autoHideDuration={2000}
        onClose={() => setCopied(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setCopied(false)}>
          Copied to clipboard!
        </Alert>
      </Snackbar>
    </Box>
  );
};