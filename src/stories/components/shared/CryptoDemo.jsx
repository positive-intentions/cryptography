import React from 'react';
import { Paper, Box, Typography, Divider } from '@mui/material';
import { styled } from '@mui/material/styles';

const StyledPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  marginBottom: theme.spacing(2),
  background: theme.palette.mode === 'dark' ? '#1e1e1e' : '#ffffff',
  border: `1px solid ${theme.palette.divider}`,
}));

const DemoContainer = styled(Box)(({ theme }) => ({
  '& .demo-section': {
    marginBottom: theme.spacing(3),
  },
  '& .demo-header': {
    marginBottom: theme.spacing(2),
  },
}));

export const CryptoDemo = ({ title, description, children }) => {
  return (
    <StyledPaper elevation={0}>
      <DemoContainer>
        {(title || description) && (
          <Box className="demo-header">
            {title && (
              <Typography variant="h5" component="h2" gutterBottom>
                {title}
              </Typography>
            )}
            {description && (
              <Typography variant="body2" color="text.secondary" paragraph>
                {description}
              </Typography>
            )}
            <Divider sx={{ my: 2 }} />
          </Box>
        )}
        {children}
      </DemoContainer>
    </StyledPaper>
  );
};