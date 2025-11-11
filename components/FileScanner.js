'use client';

import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Progress } from '@/components/ui/progress';
import { Upload, File, Eye, AlertTriangle, CheckCircle, XCircle, Code, Shield, FileText, X } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

export default function FileScanner() {
  const [files, setFiles] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  const loadDemoFiles = async () => {
    const demoFiles = [
      {
        name: 'insecure_config.json',
        size: 329,
        type: 'application/json',
        content: `{
  "database": {
    "host": "localhost",
    "port": 5432,
    "username": "admin",
    "password": "admin123",
    "api_key": "sk_test_1234567890abcdef"
  },
  "app": {
    "debug": true,
    "secret_key": "my-super-secret-key-12345"
  },
  "aws": {
    "access_token": "AKIAIOSFODNN7EXAMPLE",
    "region": "us-east-1"
  }
}`,
        id: Math.random().toString(36).substr(2, 9)
      },
      {
        name: 'vulnerable_app.py',
        size: 771,
        type: 'text/x-python',
        content: `import os
import subprocess
import pickle

def get_user_data(user_input):
    # Dangerous: Using eval with user input
    result = eval(user_input)
    return result

def execute_command(command):
    # Vulnerable to command injection
    subprocess.call(command, shell=True)

def load_data(data_file):
    # Insecure deserialization
    with open(data_file, 'rb') as f:
        data = pickle.load(f)
    return data

def query_database(user_id):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return query

def authenticate(username, password):
    # Weak authentication check
    assert username == "admin"
    assert password == "password123"
    return True

# Debug print statement
print("Application started")`,
        id: Math.random().toString(36).substr(2, 9)
      },
      {
        name: 'secure_handler.js',
        size: 892,
        type: 'text/javascript',
        content: `// Insecure JavaScript code with multiple issues

function updateContent(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
}

function processData(data) {
    // Dangerous eval usage
    var result = eval('(' + data + ')');
    return result;
}

function displayMessage(msg) {
    // Unsafe document.write
    document.write('<div>' + msg + '</div>');
}

// Console statement that should not be in production
console.log('API Key:', process.env.API_KEY);

// Using var instead of let/const
var userName = 'admin';

// Loose equality
if (userName == null) {
    console.error('User not found');
}

// React component with dangerous prop
function UserProfile({ htmlContent }) {
    return (
        <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    );
}

module.exports = { updateContent, processData, displayMessage, UserProfile };`,
        id: Math.random().toString(36).substr(2, 9)
      },
      {
        name: 'package.json',
        size: 160,
        type: 'application/json',
        content: `{
  "name": "test-application",
  "version": "1.0.0",
  "api_key": "sk_live_abc123xyz",
  "secret": "my-secret-token-2024",
  "password": "db_password_12345"
}`,
        id: Math.random().toString(36).substr(2, 9)
      }
    ];
    
    setFiles(demoFiles);
  };

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFiles(Array.from(e.dataTransfer.files));
    }
  }, []);

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(Array.from(e.target.files));
    }
  };

  const handleFiles = async (newFiles) => {
    const filesWithContent = await Promise.all(
      newFiles.map(async (file) => {
        const content = await readFileContent(file);
        return {
          name: file.name,
          size: file.size,
          type: file.type || getFileType(file.name),
          content: content,
          id: Math.random().toString(36).substr(2, 9)
        };
      })
    );
    setFiles(prev => [...prev, ...filesWithContent]);
  };

  const readFileContent = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  };

  const getFileType = (filename) => {
    const ext = filename.split('.').pop().toLowerCase();
    const types = {
      'js': 'text/javascript',
      'jsx': 'text/javascript',
      'ts': 'text/typescript',
      'tsx': 'text/typescript',
      'py': 'text/x-python',
      'json': 'application/json',
      'yaml': 'text/yaml',
      'yml': 'text/yaml',
      'xml': 'text/xml',
      'env': 'text/plain',
      'txt': 'text/plain'
    };
    return types[ext] || 'text/plain';
  };

  const removeFile = (fileId) => {
    setFiles(files.filter(f => f.id !== fileId));
  };

  const scanFiles = async () => {
    if (files.length === 0) return;
    
    setScanning(true);
    setScanProgress(0);
    
    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      const response = await fetch('/api/scan-files', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files })
      });

      const results = await response.json();
      
      clearInterval(progressInterval);
      setScanProgress(100);
      setScanResults(results);
    } catch (error) {
      console.error('Error scanning files:', error);
    } finally {
      setTimeout(() => {
        setScanning(false);
      }, 500);
    }
  };

  const previewFile = (file) => {
    setSelectedFile(file);
    setShowPreviewModal(true);
  };

  const viewIssueDetail = (issue) => {
    setSelectedIssue(issue);
    setShowDetailModal(true);
  };

  const getSeverityColor = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6" />
            File Security Scanner
          </CardTitle>
          <CardDescription>
            Upload code files to scan for security vulnerabilities and code quality issues
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Drag & Drop Area */}
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
            <p className="text-lg font-medium mb-2">Drag & drop files here</p>
            <p className="text-sm text-gray-500 mb-4">or</p>
            <div className="flex gap-3 justify-center">
              <label htmlFor="file-input" className="cursor-pointer">
                <Button type="button" onClick={() => document.getElementById('file-input').click()}>
                  Browse Files
                </Button>
              </label>
              <Button type="button" variant="outline" onClick={loadDemoFiles}>
                Load Demo Files
              </Button>
            </div>
            <input
              id="file-input"
              type="file"
              multiple
              accept=".js,.jsx,.ts,.tsx,.py,.json,.yaml,.yml,.xml,.env,.txt"
              onChange={handleFileInput}
              className="hidden"
            />
            <p className="text-xs text-gray-400 mt-4">
              Supported: .js, .py, .json, .yaml, .xml, .env, and more
            </p>
          </div>

          {/* File List */}
          {files.length > 0 && (
            <div className="space-y-2">
              <h3 className="font-medium">Files to Scan ({files.length})</h3>
              <div className="space-y-2">
                {files.map(file => (
                  <div key={file.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <File className="h-5 w-5 text-blue-500" />
                      <div>
                        <button
                          onClick={() => previewFile(file)}
                          className="text-sm font-medium hover:text-blue-600 hover:underline text-left"
                        >
                          {file.name}
                        </button>
                        <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => previewFile(file)}
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeFile(file.id)}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan Button */}
          {files.length > 0 && (
            <div className="space-y-3">
              <Button 
                onClick={scanFiles} 
                disabled={scanning}
                className="w-full"
                size="lg"
              >
                {scanning ? 'Scanning...' : 'Start Security Scan'}
              </Button>
              
              {scanning && (
                <div className="space-y-2">
                  <Progress value={scanProgress} className="w-full" />
                  <p className="text-sm text-center text-gray-600">
                    Analyzing files for security issues... {scanProgress}%
                  </p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Results */}
      {scanResults && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Scan Results</span>
              <Badge variant={scanResults.stats.totalIssues > 0 ? 'destructive' : 'success'}>
                {scanResults.stats.totalIssues} Issues Found
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Summary Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-red-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">{scanResults.stats.critical}</div>
                <div className="text-sm text-gray-600">Critical</div>
              </div>
              <div className="p-4 bg-orange-50 rounded-lg">
                <div className="text-2xl font-bold text-orange-600">{scanResults.stats.high}</div>
                <div className="text-sm text-gray-600">High</div>
              </div>
              <div className="p-4 bg-yellow-50 rounded-lg">
                <div className="text-2xl font-bold text-yellow-600">{scanResults.stats.medium}</div>
                <div className="text-sm text-gray-600">Medium</div>
              </div>
              <div className="p-4 bg-blue-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">{scanResults.stats.low}</div>
                <div className="text-sm text-gray-600">Low</div>
              </div>
            </div>

            {/* Issues List */}
            <div className="space-y-3">
              <h3 className="font-medium">Detailed Findings</h3>
              {scanResults.findings.map((finding, idx) => (
                <Alert
                  key={idx}
                  className="cursor-pointer hover:bg-gray-50 transition-colors"
                  onClick={() => viewIssueDetail(finding)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <AlertTitle className="flex items-center gap-2">
                        {finding.severity === 'critical' || finding.severity === 'high' ? (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        ) : (
                          <Shield className="h-4 w-4 text-yellow-500" />
                        )}
                        <span>{finding.title}</span>
                        <Badge className={getSeverityColor(finding.severity)}>
                          {finding.severity}
                        </Badge>
                      </AlertTitle>
                      <AlertDescription className="mt-2">
                        <p className="text-sm">{finding.description}</p>
                        <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                          <span className="flex items-center gap-1">
                            <File className="h-3 w-3" />
                            {finding.file}
                          </span>
                          {finding.line && (
                            <span>Line {finding.line}</span>
                          )}
                          <Badge variant="outline" className="text-xs">
                            {finding.category}
                          </Badge>
                        </div>
                      </AlertDescription>
                    </div>
                  </div>
                </Alert>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* File Preview Modal */}
      <Dialog open={showPreviewModal} onOpenChange={setShowPreviewModal}>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              {selectedFile?.name}
            </DialogTitle>
            <DialogDescription>
              {selectedFile && formatFileSize(selectedFile.size)} • {selectedFile?.type}
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4">
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-auto max-h-96 text-sm">
              <code>{selectedFile?.content}</code>
            </pre>
          </div>
        </DialogContent>
      </Dialog>

      {/* Issue Detail Modal */}
      <Dialog open={showDetailModal} onOpenChange={setShowDetailModal}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              {selectedIssue?.title}
            </DialogTitle>
            <DialogDescription>
              <Badge className={getSeverityColor(selectedIssue?.severity)}>
                {selectedIssue?.severity} Severity
              </Badge>
            </DialogDescription>
          </DialogHeader>
          {selectedIssue && (
            <div className="space-y-4 mt-4">
              {/* Description */}
              <div>
                <h4 className="font-semibold mb-2">Description</h4>
                <p className="text-sm text-gray-700">{selectedIssue.description}</p>
              </div>

              {/* Location */}
              <div>
                <h4 className="font-semibold mb-2">Location</h4>
                <div className="bg-gray-50 p-3 rounded">
                  <p className="text-sm"><strong>File:</strong> {selectedIssue.file}</p>
                  {selectedIssue.line && (
                    <p className="text-sm"><strong>Line:</strong> {selectedIssue.line}</p>
                  )}
                  {selectedIssue.code && (
                    <pre className="mt-2 bg-gray-900 text-gray-100 p-2 rounded text-xs overflow-auto">
                      <code>{selectedIssue.code}</code>
                    </pre>
                  )}
                </div>
              </div>

              {/* Impact */}
              {selectedIssue.impact && (
                <div>
                  <h4 className="font-semibold mb-2">Impact</h4>
                  <p className="text-sm text-gray-700">{selectedIssue.impact}</p>
                </div>
              )}

              {/* Remediation */}
              {selectedIssue.remediation && (
                <div>
                  <h4 className="font-semibold mb-2">How to Fix</h4>
                  <div className="bg-blue-50 p-3 rounded">
                    <p className="text-sm text-gray-700">{selectedIssue.remediation}</p>
                  </div>
                </div>
              )}

              {/* References */}
              {selectedIssue.references && selectedIssue.references.length > 0 && (
                <div>
                  <h4 className="font-semibold mb-2">References</h4>
                  <ul className="list-disc list-inside space-y-1">
                    {selectedIssue.references.map((ref, idx) => (
                      <li key={idx} className="text-sm text-blue-600 hover:underline">
                        <a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* CWE/CVE */}
              {selectedIssue.cwe && (
                <div>
                  <h4 className="font-semibold mb-2">Security Classification</h4>
                  <Badge variant="outline">{selectedIssue.cwe}</Badge>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
