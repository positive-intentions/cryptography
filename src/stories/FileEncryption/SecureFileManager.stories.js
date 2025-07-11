import React, { useState, useCallback } from 'react';
import { CryptographyProvider, useCryptography } from '../components/Cryptography';
import { CryptoDemo, CodeDisplay, OperationStatus } from '../components/shared';
import { 
  Button, 
  TextField, 
  Box, 
  Typography,
  Stack,
  Card,
  CardContent,
  CardHeader,
  Alert,
  Grid,
  Paper,
  Chip,
  IconButton,
  InputAdornment,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress
} from '@mui/material';
import { 
  Lock, 
  LockOpen, 
  Upload,
  Download,
  Delete,
  Visibility,
  VisibilityOff,
  Security,
  Folder,
  InsertDriveFile,
  Image,
  Description,
  VideoFile,
  AudioFile
} from '@mui/icons-material';

export default {
  title: 'Cryptography/File Encryption/Secure File Manager',
  component: CryptographyProvider,
  parameters: {
    docs: {
      description: {
        component: 'Password-based file encryption system supporting text and binary files with PBKDF2 key derivation.',
      },
    },
  },
};

const PasswordBasedFileEncryptionDemo = () => {
  const { 
    encryptTextFile,
    decryptTextFile,
    encryptBinaryFile,
    decryptBinaryFile,
    createSecureFileDownload,
    parseEncryptedFilePackage,
    decryptUploadedFile
  } = useCryptography();
  
  const [password, setPassword] = useState('demo-password-123');
  const [showPassword, setShowPassword] = useState(false);
  const [textContent, setTextContent] = useState('This is a secret document that will be encrypted!\n\nIt contains sensitive information:\n- Personal notes\n- API keys\n- Confidential data');
  const [fileName, setFileName] = useState('secret-document.txt');
  const [encryptedFiles, setEncryptedFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [decryptedContent, setDecryptedContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');
  const [activeTab, setActiveTab] = useState(0);
  const [previewDialog, setPreviewDialog] = useState({ open: false, content: '', title: '' });
  const [uploadedEncryptedFile, setUploadedEncryptedFile] = useState(null);
  const [uploadValidation, setUploadValidation] = useState(null);

  const handleEncryptText = async () => {
    if (!textContent.trim() || !password.trim()) {
      setStatus('Please enter both text content and password');
      return;
    }

    setLoading(true);
    try {
      const encrypted = await encryptTextFile(textContent, password, fileName);
      const newFile = {
        id: Date.now(),
        ...encrypted,
        type: 'text',
        isEncrypted: true
      };
      
      setEncryptedFiles(prev => [...prev, newFile]);
      setStatus(`File "${fileName}" encrypted successfully!`);
      setTextContent('');
      setFileName('secret-document.txt');
    } catch (error) {
      setStatus(`Encryption failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file || !password.trim()) {
      setStatus('Please select a file and enter a password');
      return;
    }

    setLoading(true);
    try {
      const encrypted = await encryptBinaryFile(file, password);
      const newFile = {
        id: Date.now(),
        ...encrypted,
        type: 'binary',
        isEncrypted: true,
        originalName: file.name,
        size: file.size
      };
      
      setEncryptedFiles(prev => [...prev, newFile]);
      setStatus(`File "${file.name}" encrypted successfully!`);
      event.target.value = ''; // Reset file input
    } catch (error) {
      setStatus(`Encryption failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDecryptFile = async (file) => {
    if (!password.trim()) {
      setStatus('Please enter the password to decrypt');
      return;
    }

    setLoading(true);
    try {
      if (file.type === 'text') {
        const decrypted = await decryptTextFile(file, password);
        setDecryptedContent(decrypted.textContent);
        setSelectedFile(file);
        setStatus(`File "${file.fileName}" decrypted successfully!`);
      } else {
        const decrypted = await decryptBinaryFile(file, password);
        // For binary files, we'll show metadata and offer download
        setPreviewDialog({
          open: true,
          title: `Decrypted: ${file.fileName}`,
          content: `File decrypted successfully!\n\nFile: ${file.fileName}\nType: ${file.mimeType || 'Unknown'}\nSize: ${formatFileSize(file.originalSize)}\n\nClick download to save the decrypted file.`,
          downloadData: decrypted
        });
        setStatus(`Binary file "${file.fileName}" decrypted successfully!`);
      }
    } catch (error) {
      setStatus(`Decryption failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadDecrypted = (downloadData) => {
    if (downloadData.blob) {
      createSecureFileDownload(downloadData.blob, downloadData.fileName);
    } else if (downloadData.data) {
      createSecureFileDownload(downloadData.data, downloadData.fileName, downloadData.mimeType);
    }
    setPreviewDialog({ open: false, content: '', title: '' });
  };

  const handleDownloadEncrypted = (file) => {
    const encryptedData = {
      encryptedData: file.encryptedData,
      iv: file.iv,
      salt: file.salt,
      fileName: file.fileName,
      timestamp: file.timestamp,
      originalSize: file.originalSize,
      mimeType: file.mimeType,
      type: file.type
    };
    
    const blob = new Blob([JSON.stringify(encryptedData, null, 2)], { type: 'application/json' });
    createSecureFileDownload(blob, `${file.fileName}.encrypted.json`);
    setStatus(`Encrypted file package downloaded: ${file.fileName}.encrypted.json`);
  };

  const handleDeleteFile = (fileId) => {
    setEncryptedFiles(prev => prev.filter(f => f.id !== fileId));
    if (selectedFile && selectedFile.id === fileId) {
      setSelectedFile(null);
      setDecryptedContent('');
    }
    setStatus('File deleted from session');
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileIcon = (file) => {
    if (file.type === 'text') return <Description color="primary" />;
    
    const mimeType = file.mimeType || '';
    if (mimeType.startsWith('image/')) return <Image color="success" />;
    if (mimeType.startsWith('video/')) return <VideoFile color="error" />;
    if (mimeType.startsWith('audio/')) return <AudioFile color="warning" />;
    return <InsertDriveFile color="action" />;
  };

  const handleEncryptedFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setLoading(true);
    try {
      // Validate the encrypted file package
      const validation = await parseEncryptedFilePackage(file);
      setUploadValidation(validation);
      
      if (validation.isValid) {
        setUploadedEncryptedFile(file);
        setStatus(`Encrypted file "${validation.metadata.fileName}" loaded successfully. Enter password to decrypt.`);
      } else {
        setStatus(`Invalid encrypted file: ${validation.error}`);
        setUploadedEncryptedFile(null);
      }
      
      event.target.value = ''; // Reset file input
    } catch (error) {
      setStatus(`Failed to load encrypted file: ${error.message}`);
      setUploadedEncryptedFile(null);
      setUploadValidation(null);
    } finally {
      setLoading(false);
    }
  };

  const handleDecryptUploadedFile = async () => {
    if (!uploadedEncryptedFile || !password.trim()) {
      setStatus('Please select an encrypted file and enter the password');
      return;
    }

    setLoading(true);
    try {
      const decrypted = await decryptUploadedFile(uploadedEncryptedFile, password);
      
      if (decrypted.isTextFile) {
        // Show text content directly
        setDecryptedContent(decrypted.textContent);
        setSelectedFile({
          id: 'uploaded',
          fileName: decrypted.metadata.fileName,
          type: 'text'
        });
        setStatus(`Text file "${decrypted.metadata.fileName}" decrypted successfully!`);
      } else {
        // Show binary file preview and offer download
        setPreviewDialog({
          open: true,
          title: `Decrypted: ${decrypted.metadata.fileName}`,
          content: `Encrypted file decrypted successfully!\n\nFile: ${decrypted.metadata.fileName}\nType: ${decrypted.metadata.mimeType || 'Binary'}\nSize: ${formatFileSize(decrypted.metadata.originalSize)}\n\nClick download to save the decrypted file.`,
          downloadData: {
            data: decrypted.data,
            fileName: decrypted.metadata.fileName,
            mimeType: decrypted.metadata.mimeType
          }
        });
        setStatus(`Binary file "${decrypted.metadata.fileName}" decrypted successfully!`);
      }
      
      // Clear the uploaded file after successful decryption
      setUploadedEncryptedFile(null);
      setUploadValidation(null);
    } catch (error) {
      setStatus(`Failed to decrypt uploaded file: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const createSampleFiles = async () => {
    if (!password.trim()) {
      setStatus('Please enter a password first');
      return;
    }

    setLoading(true);
    try {
      // Create multiple sample encrypted files
      const samples = [
        { content: 'API Key: sk-1234567890abcdef\nDatabase URL: postgresql://user:pass@localhost/db\nSecret Token: abc123xyz789', name: 'api-secrets.txt' },
        { content: '# Private Notes\n\n## Project Ideas\n- Build encrypted file system\n- Secure messaging app\n- Password manager\n\n## Passwords\n- GitHub: secure-token-123\n- Email: my-secret-password', name: 'private-notes.md' },
        { content: JSON.stringify({
  "environment": "production",
  "apiKeys": {
    "stripe": "sk_live_...",
    "sendgrid": "SG...",
    "aws": "AKIA..."
  },
  "database": {
    "host": "prod-db.company.com",
    "username": "admin",
    "password": "super-secret-db-pass"
  }
}, null, 2), name: 'production-config.json' }
      ];

      for (const sample of samples) {
        const encrypted = await encryptTextFile(sample.content, password, sample.name);
        const newFile = {
          id: Date.now() + Math.random(),
          ...encrypted,
          type: 'text',
          isEncrypted: true
        };
        setEncryptedFiles(prev => [...prev, newFile]);
      }

      setStatus('Sample encrypted files created successfully!');
    } catch (error) {
      setStatus(`Failed to create sample files: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CryptoDemo
      title="Password-Based File Encryption"
      description="Encrypt and decrypt files using PBKDF2 key derivation and AES-GCM encryption."
    >
      <Stack spacing={3}>
        <Alert severity="info">
          <Typography variant="body2">
            <strong>Secure File Encryption:</strong> This system uses PBKDF2 with 100,000 iterations 
            to derive encryption keys from passwords, then encrypts files with AES-GCM. 
            Each file gets a unique salt and IV for maximum security.
          </Typography>
        </Alert>

        {/* Password Input */}
        <Card>
          <CardHeader
            title="🔑 Master Password"
            subheader="Password used for encrypting and decrypting all files"
          />
          <CardContent>
            <TextField
              label="Encryption Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              fullWidth
              variant="outlined"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                )
              }}
              helperText="Use a strong password for maximum security"
            />
          </CardContent>
        </Card>

        {/* File Operations */}
        <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
          <Tab label="Encrypt Text" />
          <Tab label="Upload Files" />
          <Tab label="Encrypted Files" />
          <Tab label="Decrypt Uploaded" />
        </Tabs>

        {/* Encrypt Text Tab */}
        {activeTab === 0 && (
          <Card>
            <CardHeader
              title="📝 Encrypt Text Content"
              subheader="Create encrypted text files"
            />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="File Name"
                  value={fileName}
                  onChange={(e) => setFileName(e.target.value)}
                  fullWidth
                  variant="outlined"
                />
                
                <TextField
                  label="Text Content"
                  value={textContent}
                  onChange={(e) => setTextContent(e.target.value)}
                  multiline
                  rows={6}
                  fullWidth
                  variant="outlined"
                  placeholder="Enter the text content you want to encrypt..."
                />
                
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    onClick={handleEncryptText}
                    disabled={loading || !textContent.trim() || !password.trim()}
                    startIcon={<Lock />}
                  >
                    Encrypt Text File
                  </Button>
                  
                  <Button
                    variant="outlined"
                    onClick={createSampleFiles}
                    disabled={loading || !password.trim()}
                    startIcon={<Folder />}
                  >
                    Create Sample Files
                  </Button>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Upload Files Tab */}
        {activeTab === 1 && (
          <Card>
            <CardHeader
              title="📤 Encrypt Binary Files"
              subheader="Upload and encrypt any file type"
            />
            <CardContent>
              <Stack spacing={2}>
                <input
                  accept="*/*"
                  style={{ display: 'none' }}
                  id="file-upload"
                  type="file"
                  onChange={handleFileUpload}
                  disabled={loading || !password.trim()}
                />
                <label htmlFor="file-upload">
                  <Button
                    variant="contained"
                    component="span"
                    disabled={loading || !password.trim()}
                    startIcon={<Upload />}
                    size="large"
                  >
                    Select File to Encrypt
                  </Button>
                </label>
                
                <Typography variant="body2" color="text.secondary">
                  Supports all file types: images, documents, videos, archives, etc.
                </Typography>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Decrypt Uploaded Tab */}
        {activeTab === 3 && (
          <Card>
            <CardHeader
              title="📁 Decrypt Uploaded Files"
              subheader="Upload previously downloaded encrypted .json packages"
            />
            <CardContent>
              <Stack spacing={2}>
                <Alert severity="info">
                  <Typography variant="body2">
                    Upload encrypted .json files that were previously downloaded from this system.
                    These files contain the encrypted data, IV, salt, and metadata needed for decryption.
                  </Typography>
                </Alert>
                
                <input
                  accept=".json,.encrypted"
                  style={{ display: 'none' }}
                  id="encrypted-file-upload"
                  type="file"
                  onChange={handleEncryptedFileUpload}
                  disabled={loading}
                />
                <label htmlFor="encrypted-file-upload">
                  <Button
                    variant="outlined"
                    component="span"
                    disabled={loading}
                    startIcon={<Upload />}
                    size="large"
                    color="secondary"
                  >
                    Upload Encrypted File Package
                  </Button>
                </label>
                
                {uploadValidation && (
                  <Alert severity={uploadValidation.isValid ? 'success' : 'error'}>
                    {uploadValidation.isValid ? (
                      <Typography variant="body2">
                        <strong>Valid encrypted file loaded:</strong><br/>
                        • File: {uploadValidation.metadata.fileName}<br/>
                        • Original size: {formatFileSize(uploadValidation.metadata.originalSize)}<br/>
                        • Type: {uploadValidation.metadata.type || 'Unknown'}<br/>
                        • Encrypted: {uploadValidation.metadata.timestamp}
                      </Typography>
                    ) : (
                      <Typography variant="body2">
                        <strong>Invalid file:</strong> {uploadValidation.error}
                      </Typography>
                    )}
                  </Alert>
                )}
                
                {uploadedEncryptedFile && uploadValidation?.isValid && (
                  <Box sx={{ mt: 2 }}>
                    <Button
                      variant="contained"
                      onClick={handleDecryptUploadedFile}
                      disabled={loading || !password.trim()}
                      startIcon={<LockOpen />}
                      color="success"
                    >
                      Decrypt Uploaded File
                    </Button>
                    
                    {!password.trim() && (
                      <Typography variant="caption" color="error" sx={{ ml: 2 }}>
                        Enter password above to decrypt
                      </Typography>
                    )}
                  </Box>
                )}
                
                <Typography variant="body2" color="text.secondary">
                  <strong>Supported formats:</strong> .json files created by this encryption system
                </Typography>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Encrypted Files Tab */}
        {activeTab === 2 && (
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardHeader
                  title="🔐 Encrypted Files"
                  subheader={`${encryptedFiles.length} files in encrypted storage`}
                />
                <CardContent>
                  {encryptedFiles.length === 0 ? (
                    <Typography color="text.secondary" align="center" sx={{ py: 4 }}>
                      No encrypted files yet. Create some using the other tabs.
                    </Typography>
                  ) : (
                    <List>
                      {encryptedFiles.map((file) => (
                        <ListItem key={file.id} divider>
                          <Box sx={{ display: 'flex', alignItems: 'center', mr: 2 }}>
                            {getFileIcon(file)}
                          </Box>
                          <ListItemText
                            primary={file.fileName}
                            secondary={
                              <Box>
                                <Typography variant="caption" display="block">
                                  {file.type === 'text' ? 'Text File' : `${file.mimeType || 'Binary File'}`}
                                </Typography>
                                <Typography variant="caption" display="block">
                                  Size: {formatFileSize(file.originalSize)} • {new Date(file.timestamp).toLocaleString()}
                                </Typography>
                                <Chip 
                                  label="ENCRYPTED" 
                                  size="small" 
                                  color="error" 
                                  variant="outlined"
                                  sx={{ mt: 0.5 }}
                                />
                              </Box>
                            }
                          />
                          <ListItemSecondaryAction>
                            <Stack direction="row" spacing={1}>
                              <IconButton
                                size="small"
                                onClick={() => handleDecryptFile(file)}
                                disabled={loading}
                                title="Decrypt & View"
                              >
                                <LockOpen />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleDownloadEncrypted(file)}
                                title="Download Encrypted Package"
                              >
                                <Download />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleDeleteFile(file.id)}
                                color="error"
                                title="Delete"
                              >
                                <Delete />
                              </IconButton>
                            </Stack>
                          </ListItemSecondaryAction>
                        </ListItem>
                      ))}
                    </List>
                  )}
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              {selectedFile && decryptedContent && (
                <Card>
                  <CardHeader
                    title="🔓 Decrypted Content"
                    subheader={selectedFile.fileName}
                  />
                  <CardContent>
                    <CodeDisplay
                      code={decryptedContent}
                      label="Decrypted File Content"
                      maxHeight="400px"
                    />
                    <Button
                      variant="outlined"
                      onClick={() => createSecureFileDownload(decryptedContent, selectedFile.fileName)}
                      startIcon={<Download />}
                      sx={{ mt: 2 }}
                    >
                      Download Decrypted File
                    </Button>
                  </CardContent>
                </Card>
              )}
            </Grid>
          </Grid>
        )}

        <OperationStatus loading={loading} />

        {status && (
          <Alert severity={status.includes('failed') || status.includes('Error') ? 'error' : 'success'}>
            {status}
          </Alert>
        )}

        {/* Binary File Preview Dialog */}
        <Dialog
          open={previewDialog.open}
          onClose={() => setPreviewDialog({ open: false, content: '', title: '' })}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>{previewDialog.title}</DialogTitle>
          <DialogContent>
            <Typography variant="body1" sx={{ whiteSpace: 'pre-line' }}>
              {previewDialog.content}
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setPreviewDialog({ open: false, content: '', title: '' })}>
              Close
            </Button>
            {previewDialog.downloadData && (
              <Button 
                variant="contained" 
                onClick={() => handleDownloadDecrypted(previewDialog.downloadData)}
                startIcon={<Download />}
              >
                Download
              </Button>
            )}
          </DialogActions>
        </Dialog>

        {/* Security Information */}
        <Alert severity="info">
          <Typography variant="h6" gutterBottom>
            🔐 Security Features
          </Typography>
          <Typography component="ul" variant="body2" sx={{ mt: 1, mb: 0 }}>
            <li><strong>PBKDF2 Key Derivation:</strong> 100,000 iterations with SHA-256</li>
            <li><strong>AES-GCM Encryption:</strong> 256-bit keys with authenticated encryption</li>
            <li><strong>Unique Salt & IV:</strong> Each file gets cryptographically random values</li>
            <li><strong>Binary File Support:</strong> Handles any file type (images, documents, etc.)</li>
            <li><strong>Secure Downloads:</strong> Files are decrypted in memory before download</li>
            <li><strong>No Server Storage:</strong> All encryption happens in your browser</li>
          </Typography>
        </Alert>
      </Stack>
    </CryptoDemo>
  );
};

export const Default = () => (
  <CryptographyProvider>
    <PasswordBasedFileEncryptionDemo />
  </CryptographyProvider>
);

const DragDropFileEncryptionDemo = () => {
  const { encryptBinaryFile, decryptBinaryFile, createSecureFileDownload } = useCryptography();
  
  const [password, setPassword] = useState('secure-password-123');
  const [dragOver, setDragOver] = useState(false);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    setDragOver(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    await processFiles(droppedFiles);
  }, [password]);

  const processFiles = async (fileList) => {
    if (!password.trim()) {
      alert('Please enter a password first');
      return;
    }

    setLoading(true);
    setProgress(0);
    
    try {
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const encrypted = await encryptBinaryFile(file, password);
        
        const newFile = {
          id: Date.now() + Math.random(),
          originalFile: file,
          encrypted: encrypted,
          status: 'encrypted'
        };
        
        setFiles(prev => [...prev, newFile]);
        setProgress(((i + 1) / fileList.length) * 100);
      }
    } catch (error) {
      console.error('Encryption error:', error);
    } finally {
      setLoading(false);
      setProgress(0);
    }
  };

  const handleDecryptAndDownload = async (fileItem) => {
    try {
      const decrypted = await decryptBinaryFile(fileItem.encrypted, password);
      createSecureFileDownload(decrypted.blob, fileItem.originalFile.name);
    } catch (error) {
      alert('Decryption failed: ' + error.message);
    }
  };

  return (
    <CryptoDemo
      title="Drag & Drop File Encryption"
      description="Drag files onto the drop zone to encrypt them with your password."
    >
      <Stack spacing={3}>
        <TextField
          label="Encryption Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          fullWidth
          variant="outlined"
        />

        <Box
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          sx={{
            border: `2px dashed ${dragOver ? '#2196f3' : '#ddd'}`,
            borderRadius: 2,
            p: 4,
            textAlign: 'center',
            backgroundColor: dragOver ? '#f3f9ff' : '#fafafa',
            cursor: 'pointer',
            transition: 'all 0.3s ease',
            minHeight: 200,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center'
          }}
        >
          <Upload sx={{ fontSize: 64, color: dragOver ? 'primary.main' : 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            {dragOver ? 'Drop files here to encrypt' : 'Drag & drop files here'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Supports all file types • Multiple files allowed
          </Typography>
        </Box>

        {loading && (
          <Box>
            <Typography variant="body2" gutterBottom>
              Encrypting files... {progress.toFixed(0)}%
            </Typography>
            <LinearProgress variant="determinate" value={progress} />
          </Box>
        )}

        {files.length > 0 && (
          <Card>
            <CardHeader title="Encrypted Files" />
            <CardContent>
              <List>
                {files.map((fileItem) => (
                  <ListItem key={fileItem.id} divider>
                    <ListItemText
                      primary={fileItem.originalFile.name}
                      secondary={`${fileItem.originalFile.type} • ${(fileItem.originalFile.size / 1024).toFixed(2)} KB`}
                    />
                    <ListItemSecondaryAction>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => handleDecryptAndDownload(fileItem)}
                        startIcon={<Download />}
                      >
                        Decrypt & Download
                      </Button>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        )}
      </Stack>
    </CryptoDemo>
  );
};

export const DragDropEncryption = () => (
  <CryptographyProvider>
    <DragDropFileEncryptionDemo />
  </CryptographyProvider>
);