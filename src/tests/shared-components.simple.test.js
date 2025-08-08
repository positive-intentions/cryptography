/**
 * Simple tests for shared components to achieve coverage
 * These focus on basic functionality without complex UI interactions
 */

import React from 'react';
import { render } from '@testing-library/react';
import '@testing-library/jest-dom';

// Mock MUI components as simple divs to avoid complex styling issues
jest.mock('@mui/material', () => ({
    Box: ({ children, sx, mb, display, alignItems, gap, my, ...props }) => <div {...props}>{children}</div>,
    Paper: ({ children, elevation, ...props }) => <div {...props}>{children}</div>,
    Typography: ({ children, variant, color, gutterBottom, paragraph, component, sx, ...props }) => <div {...props}>{children}</div>,
    Button: ({ children, ...props }) => <button {...props}>{children}</button>,
    IconButton: ({ children, size, onClick, sx, ...props }) => <button onClick={onClick} {...props}>{children}</button>,
    Alert: ({ children, severity, onClose, ...props }) => <div {...props}>{children}</div>,
    CircularProgress: ({ size, ...props }) => <div {...props}>Loading</div>,
    Tooltip: ({ children, title, ...props }) => <div {...props}>{children}</div>,
    Divider: ({ sx, ...props }) => <hr {...props} />,
    Snackbar: ({ children, open, autoHideDuration, onClose, anchorOrigin, ...props }) => open ? <div {...props}>{children}</div> : null,
}));

jest.mock('@mui/material/styles', () => ({
    styled: (component) => (styles) => component,
}));

jest.mock('@mui/icons-material', () => ({
    ContentCopy: (props) => <div {...props}>Copy</div>,
    CheckCircle: (props) => <div {...props}>Check</div>,
    Error: (props) => <div {...props}>Error</div>,
    Info: (props) => <div {...props}>Info</div>,
    Warning: (props) => <div {...props}>Warning</div>,
    Visibility: (props) => <div {...props}>Visible</div>,
    VisibilityOff: (props) => <div {...props}>Hidden</div>,
}));

// Mock clipboard API
Object.assign(navigator, {
    clipboard: {
        writeText: jest.fn(() => Promise.resolve()),
    },
});

// Import components using the correct paths
import { CryptoDemo } from '../stories/components/shared/CryptoDemo.jsx';
import { CodeDisplay } from '../stories/components/shared/CodeDisplay.jsx';
import { OperationStatus } from '../stories/components/shared/OperationStatus.jsx';

describe('CryptoDemo Component Simple Tests', () => {
    test('renders with children', () => {
        const { getByText } = render(
            <CryptoDemo>
                <div>Test Content</div>
            </CryptoDemo>
        );
        expect(getByText('Test Content')).toBeInTheDocument();
    });
    
    test('renders with title', () => {
        const { getByText } = render(
            <CryptoDemo title="Test Title">
                <div>Content</div>
            </CryptoDemo>
        );
        expect(getByText('Test Title')).toBeInTheDocument();
    });
    
    test('renders with description', () => {
        const { getByText } = render(
            <CryptoDemo description="Test Description">
                <div>Content</div>
            </CryptoDemo>
        );
        expect(getByText('Test Description')).toBeInTheDocument();
    });
    
    test('renders without title and description', () => {
        const { getByText } = render(
            <CryptoDemo>
                <div>Content Only</div>
            </CryptoDemo>
        );
        expect(getByText('Content Only')).toBeInTheDocument();
    });
});

describe('CodeDisplay Component Simple Tests', () => {
    test('renders with code', () => {
        const { getByText } = render(<CodeDisplay code="test code" />);
        expect(getByText('test code')).toBeInTheDocument();
    });
    
    test('renders with label', () => {
        const { getByText } = render(<CodeDisplay code="test" label="Test Label" />);
        expect(getByText('Test Label')).toBeInTheDocument();
        expect(getByText('test')).toBeInTheDocument();
    });
    
    test('renders empty code', () => {
        const { container } = render(<CodeDisplay code="" />);
        expect(container).toBeInTheDocument();
    });
    
    test('renders with secret prop', () => {
        const { getByText } = render(<CodeDisplay code="test" secret={true} />);
        expect(getByText('••••')).toBeInTheDocument(); // Secret should be hidden by default
    });
    
    test('renders with maxHeight prop', () => {
        const { container } = render(<CodeDisplay code="long code" maxHeight="100px" />);
        expect(container).toBeInTheDocument();
    });
    
    test('renders with language prop', () => {
        const { container } = render(<CodeDisplay code="console.log('test')" language="javascript" />);
        expect(container).toBeInTheDocument();
    });
});

describe('OperationStatus Component Simple Tests', () => {
    test('renders success status', () => {
        const { getByText } = render(
            <OperationStatus success={true} message="Success message" />
        );
        expect(getByText('Success message')).toBeInTheDocument();
    });
    
    test('renders error status', () => {
        const { getByText } = render(
            <OperationStatus error="Error message" />
        );
        expect(getByText('Error message')).toBeInTheDocument();
    });
    
    test('renders loading status', () => {
        const { getByText } = render(
            <OperationStatus loading={true} />
        );
        expect(getByText('Processing...')).toBeInTheDocument();
    });
    
    test('does not render when no props are set', () => {
        const { container } = render(
            <OperationStatus />
        );
        expect(container.firstChild).toBeNull();
    });
    
    test('does not render success without message', () => {
        const { container } = render(
            <OperationStatus success={true} />
        );
        expect(container.firstChild).toBeNull();
    });
    
    test('renders success with message', () => {
        const { getByText } = render(
            <OperationStatus success={true} message="Great!" />
        );
        expect(getByText('Great!')).toBeInTheDocument();
    });
    
    test('prioritizes loading over other states', () => {
        const { getByText } = render(
            <OperationStatus loading={true} error="Error" success={true} message="Success" />
        );
        expect(getByText('Processing...')).toBeInTheDocument();
    });
    
    test('prioritizes error over success', () => {
        const { getByText } = render(
            <OperationStatus error="Error message" success={true} message="Success message" />
        );
        expect(getByText('Error message')).toBeInTheDocument();
    });
});

describe('Shared Components Index', () => {
    test('index file exports components', () => {
        expect(CryptoDemo).toBeDefined();
        expect(CodeDisplay).toBeDefined();
        expect(OperationStatus).toBeDefined();
        expect(typeof CryptoDemo).toBe('function');
        expect(typeof CodeDisplay).toBe('function');
        expect(typeof OperationStatus).toBe('function');
    });
});