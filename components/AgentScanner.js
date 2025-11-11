'use client';

import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Upload, FileCode, Shield, AlertTriangle, CheckCircle, XCircle, 
  Download, Trash2, Play, Terminal, Lock, Key, FileWarning,
  Bug, Search, Code2, Activity, Eye, X, Info
} from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import FileScanner from '@/components/FileScanner';

export default function AgentScanner() {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [scanResults, setScanResults] = useState({});
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentCommand, setCurrentCommand] = useState('test');
  const [activeTab, setActiveTab] = useState('agent-scan');
  const [previewFile, setPreviewFile] = useState(null);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [showVulnModal, setShowVulnModal] = useState(false);
  const fileInputRef = useRef(null);

  // Command definitions
  const commands = [
    { 
      value: 'test', 
      label: 'Basic Test', 
      description: 'Quick vulnerability scan',
      icon: Search,
      color: 'blue'
    },
    { 
      value: 'test_insecure', 
      label: 'Deep Insecure Scan', 
      description: 'Identify all security vulnerabilities',
      icon: AlertTriangle,
      color: 'red'
    },
    { 
      value: 'test_secure', 
      label: 'Secure Compliance Check', 
      description: 'Verify security best practices',
      icon: Shield,
      color: 'green'
    },
    { 
      value: 'test_full_secure', 
      label: 'Full Security Audit', 
      description: 'Complete security analysis with recommendations',
      icon: Lock,
      color: 'purple'
    },
    { 
      value: 'test_secrets', 
      label: 'Secrets Detection', 
      description: 'Find hardcoded credentials and API keys',
      icon: Key,
      color: 'orange'
    },
    { 
      value: 'test_cve', 
      label: 'CVE Analysis', 
      description: 'Scan for known vulnerabilities (CVE)',
      icon: Bug,
      color: 'pink'
    },
    { 
      value: 'test_dependencies', 
      label: 'Dependency Check', 
      description: 'Analyze package vulnerabilities',
      icon: Code2,
      color: 'cyan'
    },
    { 
      value: 'test_malware', 
      label: 'Malware Detection', 
      description: 'Scan for malicious code patterns',
      icon: FileWarning,
      color: 'amber'
    }
  ];

  const handleFileUpload = (e) => {
    const files = Array.from(e.target.files);
    const newFiles = files.map(file => ({
      id: Math.random().toString(36).substr(2, 9),
      name: file.name,
      size: file.size,
      type: file.type,
      content: file,
      uploadedAt: new Date().toISOString()
    }));
    setUploadedFiles(prev => [...prev, ...newFiles]);
  };

  const removeFile = (fileId) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId));
    setScanResults(prev => {
      const updated = { ...prev };
      delete updated[fileId];
      return updated;
    });
  };

  const loadDemoFiles = async () => {
    const demoFiles = [
      {
        id: 'demo-1',
        name: 'insecure_config.json',
        type: 'application/json',
        size: 356,
        content: JSON.stringify({
          database: {
            host: "localhost",
            user: "admin",
            password: "admin123",
            api_key: "sk_test_1234567890abcdefghijklmnop"
          },
          aws_access_key: "AKIAIOSFODNN7EXAMPLE",
          aws_secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          jwt_secret: "mysecret",
          stripe_secret_key: "sk_live_51234567890abcdefg",
          debug: true
        }, null, 2),
        uploadedAt: new Date().toISOString()
      },
      {
        id: 'demo-2',
        name: 'vulnerable_app.py',
        type: 'text/x-python',
        size: 1245,
        content: `import os
import pickle
import hashlib
import base64
from flask import request

# Critical: Hardcoded credentials
PASSWORD = "admin123"
API_KEY = "sk_live_abcd1234567890"
SECRET_TOKEN = "my-secret-token-12345"
DB_PASSWORD = "root@123"

# SQL Injection vulnerabilities
def login(username, password):
    # SQL Injection vulnerability - string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return execute_query(query)

def get_user_data(user_id):
    # SQL Injection via concatenation
    sql = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(sql)

# Command Injection vulnerabilities
def execute_command(cmd):
    # Command injection vulnerability
    os.system(cmd)

def backup_files(filename):
    # Command injection through user input
    os.system("tar -czf backup.tar.gz " + filename)

# Insecure deserialization
def load_data(file_path):
    # Insecure deserialization using pickle
    with open(file_path, 'rb') as f:
        return pickle.load(f)

def deserialize_session(data):
    # Dangerous deserialization
    return pickle.loads(base64.b64decode(data))

# Weak cryptography
def hash_password(password):
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data):
    # Using weak DES encryption
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# Debug mode and insecure settings
DEBUG = True
VERIFY_SSL = False

# Insecure HTTP connections
def fetch_data():
    response = requests.get("http://api.example.com/data", verify=False)
    return response.json()

# Hardcoded database connection
db_connection = "mongodb://admin:password@localhost:27017"
redis_url = "redis://:password123@localhost:6379"

# Code execution vulnerability
def evaluate_expression(expr):
    # Dangerous eval usage
    return eval(expr)

# More command injection
def ping_server(host):
    os.system("ping -c 4 " + host)

# TODO: Fix security issues
# FIXME: Remove hardcoded credentials
# HACK: Temporary workaround
print("Debug: Application started")`,
        uploadedAt: new Date().toISOString()
      },
      {
        id: 'demo-3',
        name: 'secure_handler.js',
        type: 'text/javascript',
        size: 856,
        content: `const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');

// Secure password hashing with bcrypt
async function hashPassword(password) {
  const saltRounds = 12;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(password, salt);
}

// Verify password securely
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Secure JWT token generation
function generateToken(userId) {
  return jwt.sign(
    { userId, iat: Date.now() }, 
    process.env.JWT_SECRET, 
    { expiresIn: '1h', algorithm: 'HS256' }
  );
}

// Verify JWT token
function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Input validation and sanitization
function validateInput(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }
  // Remove all non-alphanumeric characters except spaces
  const sanitized = input.replace(/[^a-zA-Z0-9\\s]/g, '');
  return sanitized.substring(0, 100);
}

// Email validation
function validateEmail(email) {
  return validator.isEmail(email);
}

// Secure random token generation
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Secure encryption using AES-256
function encryptData(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// Parameterized query example
async function getUserById(userId, db) {
  // Using parameterized query to prevent SQL injection
  const query = 'SELECT * FROM users WHERE id = ?';
  return await db.execute(query, [userId]);
}

module.exports = { 
  hashPassword, 
  verifyPassword,
  generateToken, 
  verifyToken,
  validateInput,
  validateEmail,
  generateSecureToken,
  encryptData,
  getUserById
};`,
        uploadedAt: new Date().toISOString()
      },
      {
        id: 'demo-4',
        name: 'package.json',
        type: 'application/json',
        size: 312,
        content: JSON.stringify({
          "name": "vulnerable-app",
          "version": "1.0.0",
          "description": "Demo app with vulnerable dependencies",
          "dependencies": {
            "express": "4.16.0",
            "lodash": "4.17.4",
            "moment": "2.19.3",
            "axios": "0.18.0"
          },
          "devDependencies": {
            "webpack": "4.29.0"
          }
        }, null, 2),
        uploadedAt: new Date().toISOString()
      },
      {
        id: 'demo-5',
        name: 'malware_suspect.js',
        type: 'text/javascript',
        size: 678,
        content: `const net = require('net');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

// Suspicious network connection
function connectToServer() {
  const client = net.connect({ port: 4444, host: '192.168.1.100' }, () => {
    console.log('Connected to remote server');
  });
  return client;
}

// Suspicious file download
async function downloadPayload(url) {
  const response = await fetch(url);
  const buffer = await response.arrayBuffer();
  fs.writeFileSync('/tmp/payload.exe', Buffer.from(buffer));
  // Execute downloaded file
  exec('/tmp/payload.exe');
}

// Base64 encoded suspicious code
const encodedPayload = 'ZXZhbCgnYWxlcnQoIkhhY2tlZCIpJyk=';
function decodeAndExecute() {
  const decoded = Buffer.from(encodedPayload, 'base64').toString();
  eval(decoded);
}

// Command injection
function runSystemCommand(userInput) {
  exec('ls -la ' + userInput, (error, stdout) => {
    console.log(stdout);
  });
}

// Insecure deserialization
const pickle = require('pickle');
function loadUserSession(sessionData) {
  return pickle.loads(sessionData);
}

// Obfuscated code pattern
const a = () => eval(atob('Y29uc29sZS5sb2coJ2hpZGRlbicpOw=='));

// Suspicious registry/system access
function modifySystem() {
  exec('reg add HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run');
}

module.exports = { 
  connectToServer, 
  downloadPayload, 
  decodeAndExecute,
  runSystemCommand 
};`,
        uploadedAt: new Date().toISOString()
      }
    ];
    
    setUploadedFiles(prev => [...prev, ...demoFiles]);
  };

  const scanFile = async (fileId, command) => {
    const file = uploadedFiles.find(f => f.id === fileId);
    if (!file) return;

    setScanning(true);
    setScanProgress(0);

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + 5;
      });
    }, 200);

    try {
      const formData = new FormData();
      if (file.content instanceof File || file.content instanceof Blob) {
        formData.append('file', file.content);
      } else {
        // For demo files, create a blob
        const blob = new Blob([file.content], { type: file.type });
        formData.append('file', blob, file.name);
      }
      formData.append('command', command);

      const response = await fetch('/api/agent-scan', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      
      clearInterval(progressInterval);
      setScanProgress(100);

      setScanResults(prev => ({
        ...prev,
        [fileId]: result
      }));

      setTimeout(() => {
        setScanning(false);
        setScanProgress(0);
      }, 500);
    } catch (error) {
      clearInterval(progressInterval);
      console.error('Scan error:', error);
      setScanning(false);
      setScanProgress(0);
    }
  };

  const scanAllFiles = async () => {
    for (const file of uploadedFiles) {
      await scanFile(file.id, currentCommand);
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  };

  const exportResults = () => {
    const data = {
      timestamp: new Date().toISOString(),
      command: currentCommand,
      files: uploadedFiles.map(f => ({
        name: f.name,
        results: scanResults[f.id]
      }))
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-scan-${Date.now()}.json`;
    a.click();
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 dark:bg-red-950 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 dark:bg-orange-950 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-950 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 dark:bg-blue-950 border-blue-200';
      default: return 'text-slate-600 bg-slate-50 dark:bg-slate-950 border-slate-200';
    }
  };

  const openFilePreview = (file) => {
    setPreviewFile(file);
    setShowPreviewModal(true);
  };

  const openVulnerabilityDetail = (vuln, fileContext) => {
    setSelectedVulnerability({ ...vuln, fileContext });
    setShowVulnModal(true);
  };

  const getPassedTests = (result) => {
    const allTestTypes = [
      'Hardcoded Credentials',
      'SQL Injection',
      'Command Injection',
      'Insecure Deserialization',
      'Weak Cryptography',
      'Debug Mode',
      'Insecure HTTP',
      'CVE Analysis'
    ];
    
    const foundIssues = new Set(result.vulnerabilities.map(v => {
      if (v.title.includes('Password') || v.title.includes('Key') || v.title.includes('Token')) return 'Hardcoded Credentials';
      if (v.title.includes('SQL Injection')) return 'SQL Injection';
      if (v.title.includes('Command Injection')) return 'Command Injection';
      if (v.title.includes('Deserialization')) return 'Insecure Deserialization';
      if (v.title.includes('Crypto') || v.title.includes('Hash') || v.title.includes('Encryption')) return 'Weak Cryptography';
      if (v.title.includes('Debug')) return 'Debug Mode';
      if (v.title.includes('HTTP') || v.title.includes('SSL')) return 'Insecure HTTP';
      if (v.cve) return 'CVE Analysis';
      return null;
    }));
    
    return allTestTypes.filter(test => !foundIssues.has(test));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="border-2 border-purple-200 dark:border-purple-800">
        <CardHeader className="bg-purple-50 dark:bg-purple-950">
          <CardTitle className="flex items-center gap-2">
            <Terminal className="h-6 w-6 text-purple-600" />
            Agent Scanner - File Security Analysis
          </CardTitle>
          <CardDescription>
            Upload files for comprehensive security scanning using advanced CLI commands
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Tabs for different scanning modes */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="agent-scan" className="gap-2">
            <Terminal className="h-4 w-4" />
            Agent CLI Scanner
          </TabsTrigger>
          <TabsTrigger value="file-scan" className="gap-2">
            <Shield className="h-4 w-4" />
            File Security Scanner
          </TabsTrigger>
        </TabsList>

        {/* Agent CLI Scanner Tab */}
        <TabsContent value="agent-scan" className="space-y-6">
          <Card>
            <CardContent className="pt-6">
              <div className="flex flex-wrap gap-3">
                <Button onClick={() => fileInputRef.current?.click()} className="gap-2">
                  <Upload className="h-4 w-4" />
                  Upload Files
                </Button>
                <Button onClick={loadDemoFiles} variant="outline" className="gap-2">
                  <FileCode className="h-4 w-4" />
                  Load Demo Files
                </Button>
                <Button 
                  onClick={scanAllFiles} 
                  disabled={uploadedFiles.length === 0 || scanning}
                  variant="secondary"
                  className="gap-2"
                >
                  <Play className="h-4 w-4" />
                  Scan All Files
                </Button>
                {Object.keys(scanResults).length > 0 && (
                  <Button onClick={exportResults} variant="outline" className="gap-2">
                    <Download className="h-4 w-4" />
                    Export Results
                  </Button>
                )}
              </div>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                onChange={handleFileUpload}
                className="hidden"
              />
            </CardContent>
          </Card>

      {/* Command Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Scan Commands</CardTitle>
          <CardDescription>Choose your scanning strategy</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {commands.map(cmd => {
              const Icon = cmd.icon;
              const isActive = currentCommand === cmd.value;
              return (
                <button
                  key={cmd.value}
                  onClick={() => setCurrentCommand(cmd.value)}
                  className={`p-4 border-2 rounded-lg text-left transition-all hover:shadow-md ${
                    isActive 
                      ? `border-${cmd.color}-400 bg-${cmd.color}-50 dark:bg-${cmd.color}-950` 
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300'
                  }`}
                >
                  <Icon className={`h-5 w-5 mb-2 text-${cmd.color}-600`} />
                  <div className="font-medium text-sm mb-1">{cmd.label}</div>
                  <div className="text-xs text-slate-600 dark:text-slate-400">{cmd.description}</div>
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Scanning Progress */}
      {scanning && (
        <Card className="border-2 border-blue-200 dark:border-blue-800">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3 mb-3">
              <Activity className="h-5 w-5 text-blue-600 animate-pulse" />
              <span className="font-medium">Scanning in progress...</span>
            </div>
            <Progress value={scanProgress} className="h-2" />
            <div className="text-sm text-slate-600 dark:text-slate-400 mt-2">
              {scanProgress}% complete
            </div>
          </CardContent>
        </Card>
      )}

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="grid gap-4">
          {uploadedFiles.map(file => {
            const result = scanResults[file.id];
            return (
              <Card key={file.id} className="border-2">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <FileCode className="h-5 w-5 text-slate-600 mt-1" />
                      <div className="flex-1">
                        <CardTitle className="text-lg">{file.name}</CardTitle>
                        <CardDescription>
                          {formatFileSize(file.size)} • {file.type || 'Unknown type'}
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openFilePreview(file)}
                        className="gap-2"
                      >
                        <Eye className="h-3 w-3" />
                        Preview
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => scanFile(file.id, currentCommand)}
                        disabled={scanning}
                        className="gap-2"
                      >
                        <Play className="h-3 w-3" />
                        Scan
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeFile(file.id)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                {result && (
                  <CardContent>
                    <Tabs defaultValue="summary" className="w-full">
                      <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="summary">Summary</TabsTrigger>
                        <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                        <TabsTrigger value="details">Details</TabsTrigger>
                      </TabsList>

                      <TabsContent value="summary" className="space-y-4">
                        <div className="grid grid-cols-4 gap-4">
                          <div className="text-center p-4 border rounded-lg">
                            <div className={`text-2xl font-bold ${
                              result.summary.totalIssues === 0 ? 'text-green-600' : 
                              result.summary.totalIssues < 5 ? 'text-yellow-600' : 'text-red-600'
                            }`}>
                              {result.summary.totalIssues}
                            </div>
                            <div className="text-xs text-slate-600 dark:text-slate-400 mt-1">Failed Tests</div>
                          </div>
                          <div className="text-center p-4 border rounded-lg">
                            <div className="text-2xl font-bold text-green-600">{getPassedTests(result).length}</div>
                            <div className="text-xs text-slate-600 dark:text-slate-400 mt-1">Passed Tests</div>
                          </div>
                          <div className="text-center p-4 border rounded-lg">
                            <div className="text-2xl font-bold text-red-600">{result.summary.critical}</div>
                            <div className="text-xs text-slate-600 dark:text-slate-400 mt-1">Critical</div>
                          </div>
                          <div className="text-center p-4 border rounded-lg">
                            <div className={`text-2xl font-bold ${
                              result.summary.securityScore >= 80 ? 'text-green-600' : 
                              result.summary.securityScore >= 50 ? 'text-yellow-600' : 'text-red-600'
                            }`}>
                              {result.summary.securityScore}
                            </div>
                            <div className="text-xs text-slate-600 dark:text-slate-400 mt-1">Security Score</div>
                          </div>
                        </div>

                        {/* Passed Tests */}
                        {getPassedTests(result).length > 0 && (
                          <div className="p-4 border-2 border-green-200 dark:border-green-800 rounded-lg bg-green-50/50 dark:bg-green-950/50">
                            <div className="flex items-center gap-2 mb-3">
                              <CheckCircle className="h-5 w-5 text-green-600" />
                              <h4 className="font-semibold text-green-900 dark:text-green-100">Passed Security Tests</h4>
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                              {getPassedTests(result).map((test, idx) => (
                                <div key={idx} className="flex items-center gap-2 text-sm text-green-700 dark:text-green-300">
                                  <CheckCircle className="h-3 w-3" />
                                  <span>{test}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <Alert className={result.summary.securityScore >= 70 ? 'border-green-200' : 'border-red-200'}>
                          {result.summary.securityScore >= 70 ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-600" />
                          )}
                          <AlertTitle>Security Assessment</AlertTitle>
                          <AlertDescription>
                            {result.summary.status}
                          </AlertDescription>
                        </Alert>
                      </TabsContent>

                      <TabsContent value="vulnerabilities" className="space-y-3">
                        {result.vulnerabilities && result.vulnerabilities.length > 0 ? (
                          <>
                            <div className="flex items-center justify-between mb-3 p-3 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200">
                              <div className="flex items-center gap-2">
                                <XCircle className="h-5 w-5 text-red-600" />
                                <span className="font-semibold text-sm">Failed Tests: {result.vulnerabilities.length}</span>
                              </div>
                              <span className="text-xs text-slate-600 dark:text-slate-400">Click any test for details</span>
                            </div>
                            {result.vulnerabilities.map((vuln, idx) => (
                              <div 
                                key={idx} 
                                className={`p-4 border-2 rounded-lg cursor-pointer transition-all hover:shadow-md ${getSeverityColor(vuln.severity)}`}
                                onClick={() => openVulnerabilityDetail(vuln, file)}
                              >
                                <div className="flex items-start justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <AlertTriangle className="h-4 w-4" />
                                    <span className="font-semibold text-sm">{vuln.title}</span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <Badge variant={vuln.severity === 'critical' ? 'destructive' : 'secondary'}>
                                      {vuln.severity}
                                    </Badge>
                                    <Info className="h-4 w-4 text-slate-400" />
                                  </div>
                                </div>
                                <p className="text-sm mb-2">{vuln.description}</p>
                                {vuln.line && (
                                  <div className="text-xs font-mono bg-slate-900 text-slate-100 p-2 rounded">
                                    Line {vuln.line}: {vuln.code}
                                  </div>
                                )}
                                {vuln.cve && (
                                  <div className="mt-2">
                                    <Badge variant="outline" className="text-xs">{vuln.cve}</Badge>
                                  </div>
                                )}
                              </div>
                            ))}
                          </>
                        ) : (
                          <Alert className="border-green-200">
                            <CheckCircle className="h-4 w-4 text-green-600" />
                            <AlertTitle>No Vulnerabilities Found</AlertTitle>
                            <AlertDescription>
                              This file passed all security checks.
                            </AlertDescription>
                          </Alert>
                        )}
                      </TabsContent>

                      <TabsContent value="details" className="space-y-3">
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm p-2 border-b">
                            <span className="text-slate-600 dark:text-slate-400">Scan Command:</span>
                            <span className="font-mono font-medium">{result.command}</span>
                          </div>
                          <div className="flex justify-between text-sm p-2 border-b">
                            <span className="text-slate-600 dark:text-slate-400">Scan Duration:</span>
                            <span className="font-medium">{result.scanTime}ms</span>
                          </div>
                          <div className="flex justify-between text-sm p-2 border-b">
                            <span className="text-slate-600 dark:text-slate-400">Lines Analyzed:</span>
                            <span className="font-medium">{result.linesAnalyzed}</span>
                          </div>
                          <div className="flex justify-between text-sm p-2 border-b">
                            <span className="text-slate-600 dark:text-slate-400">File Type:</span>
                            <span className="font-medium">{result.fileType}</span>
                          </div>
                        </div>

                        {result.recommendations && result.recommendations.length > 0 && (
                          <div className="mt-4">
                            <h4 className="font-semibold text-sm mb-3">Security Recommendations:</h4>
                            <ul className="space-y-2">
                              {result.recommendations.map((rec, idx) => (
                                <li key={idx} className="flex items-start gap-2 text-sm">
                                  <CheckCircle className="h-4 w-4 text-green-600 mt-0.5 flex-shrink-0" />
                                  <span>{rec}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>
      )}

      {uploadedFiles.length === 0 && (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center py-12">
              <Upload className="h-12 w-12 text-slate-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">No Files Uploaded</h3>
              <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                Upload files or load demo files to start security scanning
              </p>
              <div className="flex gap-3 justify-center">
                <Button onClick={() => fileInputRef.current?.click()} className="gap-2">
                  <Upload className="h-4 w-4" />
                  Upload Files
                </Button>
                <Button onClick={loadDemoFiles} variant="outline" className="gap-2">
                  <FileCode className="h-4 w-4" />
                  Load Demo Files
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
        </TabsContent>

        {/* File Security Scanner Tab */}
        <TabsContent value="file-scan">
          <FileScanner />
        </TabsContent>
      </Tabs>

      {/* File Preview Modal */}
      <Dialog open={showPreviewModal} onOpenChange={setShowPreviewModal}>
        <DialogContent className="max-w-4xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5" />
              File Preview: {previewFile?.name}
            </DialogTitle>
            <DialogDescription>
              {previewFile?.type} • {formatFileSize(previewFile?.size || 0)}
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4 max-h-[70vh] overflow-y-auto">
            <div className="bg-slate-900 text-slate-100 p-4 rounded-lg font-mono text-sm">
              <pre className="whitespace-pre-wrap break-words">
                {typeof previewFile?.content === 'string' 
                  ? previewFile.content 
                  : 'File preview not available'}
              </pre>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Vulnerability Detail Modal */}
      <Dialog open={showVulnModal} onOpenChange={setShowVulnModal}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          {selectedVulnerability && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3 text-xl">
                  <AlertTriangle className={`h-6 w-6 ${
                    selectedVulnerability.severity === 'critical' ? 'text-red-600' :
                    selectedVulnerability.severity === 'high' ? 'text-orange-600' :
                    selectedVulnerability.severity === 'medium' ? 'text-yellow-600' :
                    'text-blue-600'
                  }`} />
                  {selectedVulnerability.title}
                </DialogTitle>
                <DialogDescription>
                  Detailed vulnerability analysis and remediation guidance
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-6 pt-4">
                {/* Overview */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Info className="h-4 w-4" />
                    Overview
                  </h3>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">Severity Level</div>
                      <Badge variant={selectedVulnerability.severity === 'critical' ? 'destructive' : 'secondary'} className="text-sm">
                        {selectedVulnerability.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">Affected File</div>
                      <div className="text-sm font-mono">{selectedVulnerability.fileContext?.name}</div>
                    </div>
                  </div>
                  {selectedVulnerability.cve && (
                    <div className="p-3 bg-red-50 dark:bg-red-950 rounded-lg border border-red-200">
                      <div className="flex items-center gap-2 mb-2">
                        <Bug className="h-4 w-4 text-red-600" />
                        <span className="font-semibold text-sm">CVE Reference</span>
                      </div>
                      <div className="text-sm font-mono">{selectedVulnerability.cve}</div>
                    </div>
                  )}
                </div>

                {/* Description */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <FileWarning className="h-4 w-4" />
                    Vulnerability Description
                  </h3>
                  <div className="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg border">
                    <p className="text-sm leading-relaxed">{selectedVulnerability.description}</p>
                  </div>
                </div>

                {/* Code Location */}
                {selectedVulnerability.line && (
                  <div>
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Code2 className="h-4 w-4" />
                      Vulnerable Code
                    </h3>
                    <div className="bg-slate-900 text-slate-100 p-4 rounded-lg border-2 border-red-500">
                      <div className="text-xs text-slate-400 mb-2">Line {selectedVulnerability.line}</div>
                      <pre className="font-mono text-sm overflow-x-auto">{selectedVulnerability.code}</pre>
                    </div>
                  </div>
                )}

                {/* Impact Analysis */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Impact Analysis
                  </h3>
                  <div className="p-4 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200">
                    <h4 className="font-semibold text-sm mb-2">Security Impact:</h4>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                        <span>This vulnerability could lead to unauthorized access, data breaches, or system compromise.</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                        <span>Exploitation difficulty: {selectedVulnerability.severity === 'critical' ? 'Low - easily exploitable' : selectedVulnerability.severity === 'high' ? 'Medium' : 'High'}</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                        <span>Risk to production: {selectedVulnerability.severity === 'critical' ? 'Critical - immediate action required' : selectedVulnerability.severity === 'high' ? 'High - prioritize remediation' : 'Medium - address in next security update'}</span>
                      </li>
                    </ul>
                  </div>
                </div>

                {/* Remediation Steps */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-600" />
                    Remediation Steps
                  </h3>
                  <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200">
                    <div className="space-y-3">
                      <div className="flex items-start gap-3">
                        <div className="flex-shrink-0 w-6 h-6 rounded-full bg-green-600 text-white flex items-center justify-center text-xs font-bold">1</div>
                        <div className="flex-1">
                          <p className="text-sm font-semibold mb-1">Immediate Action</p>
                          <p className="text-sm">{selectedVulnerability.recommendation}</p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <div className="flex-shrink-0 w-6 h-6 rounded-full bg-green-600 text-white flex items-center justify-center text-xs font-bold">2</div>
                        <div className="flex-1">
                          <p className="text-sm font-semibold mb-1">Verification</p>
                          <p className="text-sm">After applying the fix, run security tests again to verify the vulnerability has been resolved.</p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <div className="flex-shrink-0 w-6 h-6 rounded-full bg-green-600 text-white flex items-center justify-center text-xs font-bold">3</div>
                        <div className="flex-1">
                          <p className="text-sm font-semibold mb-1">Prevention</p>
                          <p className="text-sm">Implement code review processes and automated security scanning in your CI/CD pipeline to prevent similar issues.</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Compliance & Standards */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Lock className="h-4 w-4" />
                    Compliance & Standards
                  </h3>
                  <div className="grid grid-cols-3 gap-2">
                    {['OWASP Top 10', 'CWE', 'SANS Top 25', 'PCI-DSS', 'HIPAA', 'GDPR'].map((standard, idx) => (
                      <div key={idx} className="p-2 bg-slate-100 dark:bg-slate-800 rounded text-center">
                        <div className="text-xs font-semibold">{standard}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* References */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Info className="h-4 w-4" />
                    Additional Resources
                  </h3>
                  <div className="space-y-2">
                    <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="block p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 hover:bg-blue-100 dark:hover:bg-blue-900 transition-colors">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-blue-600" />
                        <span className="text-sm font-medium">OWASP Top 10 Security Risks</span>
                      </div>
                    </a>
                    {selectedVulnerability.cve && (
                      <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedVulnerability.cve}`} target="_blank" rel="noopener noreferrer" className="block p-3 bg-red-50 dark:bg-red-950 rounded-lg border border-red-200 hover:bg-red-100 dark:hover:bg-red-900 transition-colors">
                        <div className="flex items-center gap-2">
                          <Bug className="h-4 w-4 text-red-600" />
                          <span className="text-sm font-medium">View CVE Details</span>
                        </div>
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
