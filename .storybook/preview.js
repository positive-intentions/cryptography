import '@fontsource/roboto/300.css';
import '@fontsource/roboto/400.css';
import '@fontsource/roboto/500.css';
import '@fontsource/roboto/700.css';
import '@fontsource/material-icons';

import { CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import { useDarkMode } from 'storybook-dark-mode';
import React from 'react';

const lightTheme = createTheme({
  palette: {
    mode: 'light',
  },
});

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
  },
});

export const decorators = [
  (Story) => {
    const isDarkMode = useDarkMode();
    const theme = isDarkMode ? darkTheme : lightTheme;
    
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Story />
      </ThemeProvider>
    );
  },
];

/** @type { import('@storybook/react').Preview } */
const preview = {
  parameters: {
    actions: { argTypesRegex: "^on[A-Z].*" },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    docs: {
      toc: true,
    },
    options: {
      storySort: {
        order: [
          'Cryptography',
          ['Introduction', 'Random Generation', 'Hashing', 'Asymmetric', 'Symmetric', 'Use Cases', 'Performance'],
        ],
      },
    },
  },
};

export default preview;
