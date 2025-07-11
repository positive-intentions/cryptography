import React from 'react';
import { Alert, CircularProgress, Box } from '@mui/material';

export const OperationStatus = ({ loading, error, success, message }) => {
  if (loading) {
    return (
      <Box display="flex" alignItems="center" gap={2} my={2}>
        <CircularProgress size={20} />
        <span>Processing...</span>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ my: 2 }}>
        {error}
      </Alert>
    );
  }

  if (success && message) {
    return (
      <Alert severity="success" sx={{ my: 2 }}>
        {message}
      </Alert>
    );
  }

  return null;
};