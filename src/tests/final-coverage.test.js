/**
 * Final tests to achieve 100% code coverage
 * Targeting specific uncovered lines and branches
 */

import React, { useState } from 'react';
import { render, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';

// Mock MUI components with simple implementations that handle common props
jest.mock('@mui/material', () => ({
    Box: ({ children, sx, mb, display, position, top, right, gap, ...props }) => <div data-testid="box" {...props}>{children}</div>,
    Paper: ({ children, elevation, ...props }) => <div data-testid="paper" {...props}>{children}</div>,
    Typography: ({ children, variant, color, gutterBottom, paragraph, component, sx, ...props }) => <div data-testid="typography" {...props}>{children}</div>,
    Button: ({ children, onClick, ...props }) => (
        <button data-testid="button" onClick={onClick} {...props}>{children}</button>
    ),
    IconButton: ({ children, onClick, size, sx, ...props }) => (
        <button data-testid="icon-button" onClick={onClick} {...props}>{children}</button>
    ),
    Alert: ({ children, severity, onClose, ...props }) => <div data-testid="alert" {...props}>{children}</div>,
    CircularProgress: ({ size, ...props }) => <div data-testid="progress" {...props}>Loading</div>,
    Tooltip: ({ children, title, ...props }) => (
        <div data-testid="tooltip" title={title} {...props}>{children}</div>
    ),
    Divider: ({ sx, ...props }) => <hr data-testid="divider" {...props} />,
    Snackbar: ({ children, open, onClose, autoHideDuration, anchorOrigin, ...props }) => 
        open ? <div data-testid="snackbar" {...props}><button onClick={onClose}>Close</button>{children}</div> : null,
}));

jest.mock('@mui/material/styles', () => ({
    styled: (Component) => (styles) => Component,
    useTheme: () => ({
        spacing: (factor) => `${8 * factor}px`,
        palette: {
            mode: 'light',
            divider: '#e0e0e0',
        },
    }),
}));

jest.mock('@mui/icons-material', () => ({
    ContentCopy: () => <div data-testid="copy-icon">Copy</div>,
    CheckCircle: () => <div data-testid="check-icon">Check</div>,
    Visibility: () => <div data-testid="visible-icon">Visible</div>,
    VisibilityOff: () => <div data-testid="hidden-icon">Hidden</div>,
}));

// Mock clipboard API
Object.assign(navigator, {
    clipboard: {
        writeText: jest.fn(() => Promise.resolve()),
    },
});

import { CryptoDemo } from '../stories/components/shared/CryptoDemo.jsx';
import { CodeDisplay } from '../stories/components/shared/CodeDisplay.jsx';

describe('Final Coverage Tests', () => {
    
    beforeEach(() => {
        jest.clearAllMocks();
    });
    
    describe('CodeDisplay interactive features', () => {
        test('copy functionality with success feedback', async () => {
            const { getByTestId } = render(
                <CodeDisplay code="test code" />
            );
            
            const copyButton = getByTestId('icon-button');
            
            await act(async () => {
                fireEvent.click(copyButton);
            });
            
            expect(navigator.clipboard.writeText).toHaveBeenCalledWith('test code');
        });
        
        test('copy error handling', async () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
            navigator.clipboard.writeText.mockRejectedValue(new Error('Copy failed'));
            
            const { getByTestId } = render(
                <CodeDisplay code="test" />
            );
            
            await act(async () => {
                fireEvent.click(getByTestId('icon-button'));
            });
            
            await waitFor(() => {
                expect(consoleSpy).toHaveBeenCalled();
            });
            
            consoleSpy.mockRestore();
        });
        
        test('visibility toggle functionality for secret content', () => {
            const { getAllByTestId } = render(
                <CodeDisplay code="secret" secret={true} />
            );
            
            // Should have both copy button and visibility toggle when secret is true
            const buttons = getAllByTestId('icon-button');
            expect(buttons).toHaveLength(2); // visibility toggle + copy button
        });
        
        test('renders long code without issues', () => {
            const longCode = 'a'.repeat(100);
            const { container } = render(
                <CodeDisplay code={longCode} />
            );
            
            expect(container).toBeInTheDocument();
        });
        
        test('copy button is always present', () => {
            const { queryByTestId } = render(
                <CodeDisplay code="test" />
            );
            
            // CodeDisplay always shows copy button
            expect(queryByTestId('icon-button')).toBeInTheDocument();
        });
        
        test('with label', () => {
            const { getByText } = render(
                <CodeDisplay code="test" label="Code:" />
            );
            
            expect(getByText('Code:')).toBeInTheDocument();
        });
        
        test('with secret state hides content', () => {
            const { getByText } = render(
                <CodeDisplay code="secret" secret={true} />
            );
            
            // Secret content should be hidden with dots
            expect(getByText('••••••')).toBeInTheDocument();
        });
        
        test('handles click events', () => {
            const { getByTestId } = render(
                <CodeDisplay code="test" />
            );
            
            const button = getByTestId('icon-button');
            expect(button).toBeInTheDocument();
            
            // Just test that clicking doesn't throw
            expect(() => {
                fireEvent.click(button);
            }).not.toThrow();
        });
    });
    
    describe('CryptoDemo component', () => {
        test('with title and description', () => {
            const { getByText, getByTestId } = render(
                <CryptoDemo title="Test Title" description="Test Description">
                    <div>Content</div>
                </CryptoDemo>
            );
            
            expect(getByText('Test Title')).toBeInTheDocument();
            expect(getByText('Test Description')).toBeInTheDocument();
            expect(getByTestId('divider')).toBeInTheDocument();
        });
        
        test('without title and description', () => {
            const { getByText, queryByTestId } = render(
                <CryptoDemo>
                    <div>Just Content</div>
                </CryptoDemo>
            );
            
            expect(getByText('Just Content')).toBeInTheDocument();
            expect(queryByTestId('divider')).not.toBeInTheDocument();
        });
        
        test('with only title', () => {
            const { getByText, getByTestId } = render(
                <CryptoDemo title="Only Title">
                    <div>Content</div>
                </CryptoDemo>
            );
            
            expect(getByText('Only Title')).toBeInTheDocument();
            expect(getByTestId('divider')).toBeInTheDocument();
        });
        
        test('with only description', () => {
            const { getByText, getByTestId } = render(
                <CryptoDemo description="Only Description">
                    <div>Content</div>
                </CryptoDemo>
            );
            
            expect(getByText('Only Description')).toBeInTheDocument();
            expect(getByTestId('divider')).toBeInTheDocument();
        });
    });
    
    describe('Index file coverage', () => {
        test('imports all exports from index', () => {
            const exports = require('../stories/components/shared/index.js');
            
            expect(exports.CryptoDemo).toBeDefined();
            expect(exports.CodeDisplay).toBeDefined();
            expect(exports.OperationStatus).toBeDefined();
        });
    });
});