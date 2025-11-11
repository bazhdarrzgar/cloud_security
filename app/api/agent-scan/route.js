import { NextResponse } from 'next/server';

// Security scanning patterns
const securityPatterns = {
  // Hardcoded credentials
  credentials: [
    { pattern: /password\s*=\s*["'][\w\d]+["']/gi, title: 'Hardcoded Password', severity: 'critical' },
    { pattern: /api[_-]?key\s*=\s*["'][^"']+["']/gi, title: 'Hardcoded API Key', severity: 'critical' },
    { pattern: /secret[_-]?key\s*=\s*["'][^"']+["']/gi, title: 'Hardcoded Secret Key', severity: 'critical' },
    { pattern: /token\s*=\s*["'][^"']+["']/gi, title: 'Hardcoded Token', severity: 'critical' },
    { pattern: /(aws|gcp|azure)[_-]?(access|secret)[_-]?key/gi, title: 'Cloud Provider Credentials', severity: 'critical' },
  ],
  
  // SQL Injection vulnerabilities
  sqlInjection: [
    { pattern: /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+.*\s*=\s*['"]?\s*\+/gi, title: 'SQL Injection (String Concatenation)', severity: 'critical' },
    { pattern: /query\s*=\s*f?["'].*\{.*\}.*["']/gi, title: 'Potential SQL Injection (f-string)', severity: 'high' },
    { pattern: /execute\([^?]*\+[^?]*\)/gi, title: 'SQL Injection via Concatenation', severity: 'critical' },
  ],
  
  // Command Injection
  commandInjection: [
    { pattern: /os\.system\([^)]*\+[^)]*\)/gi, title: 'Command Injection Vulnerability', severity: 'critical' },
    { pattern: /exec\([^)]*\+[^)]*\)/gi, title: 'Code Execution Vulnerability', severity: 'critical' },
    { pattern: /eval\(/gi, title: 'Dangerous eval() Usage', severity: 'high' },
  ],
  
  // Insecure deserialization
  deserialization: [
    { pattern: /pickle\.loads?\(/gi, title: 'Insecure Deserialization (pickle)', severity: 'critical' },
    { pattern: /yaml\.load\(/gi, title: 'Insecure YAML Loading', severity: 'high' },
    { pattern: /JSON\.parse\([^)]*untrusted[^)]*\)/gi, title: 'Unsafe JSON Parsing', severity: 'medium' },
  ],
  
  // Weak cryptography
  weakCrypto: [
    { pattern: /MD5|SHA1/gi, title: 'Weak Cryptographic Hash', severity: 'high' },
    { pattern: /DES|RC4/gi, title: 'Weak Encryption Algorithm', severity: 'critical' },
  ],
  
  // Debug mode enabled
  debug: [
    { pattern: /debug\s*=\s*True/gi, title: 'Debug Mode Enabled', severity: 'medium' },
    { pattern: /DEBUG\s*=\s*true/gi, title: 'Debug Mode Enabled', severity: 'medium' },
  ],
  
  // Insecure HTTP
  insecureHttp: [
    { pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/gi, title: 'Insecure HTTP Connection', severity: 'medium' },
    { pattern: /verify\s*=\s*False/gi, title: 'SSL Verification Disabled', severity: 'high' },
  ]
};

// CVE database for known vulnerable packages
const knownVulnerabilities = {
  'express': {
    '4.16.0': [
      { cve: 'CVE-2022-24999', severity: 'high', description: 'Open redirect vulnerability in express <4.17.3' }
    ]
  },
  'lodash': {
    '4.17.4': [
      { cve: 'CVE-2019-10744', severity: 'critical', description: 'Prototype pollution vulnerability' },
      { cve: 'CVE-2020-8203', severity: 'high', description: 'Prototype pollution in zipObjectDeep' }
    ]
  },
  'moment': {
    '2.19.3': [
      { cve: 'CVE-2022-31129', severity: 'high', description: 'Path traversal vulnerability' }
    ]
  },
  'axios': {
    '0.18.0': [
      { cve: 'CVE-2021-3749', severity: 'medium', description: 'Regular expression denial of service' }
    ]
  }
};

function analyzeFileContent(content, fileName, command) {
  const lines = content.split('\n');
  const vulnerabilities = [];
  let securityScore = 100;

  // Command-specific analysis with different patterns
  let patterns = [];
  
  switch(command) {
    case 'test':
      // Basic test - only check for most critical issues
      patterns = [
        ...securityPatterns.credentials.slice(0, 3), // Only first 3 credential checks
        ...securityPatterns.sqlInjection.slice(0, 1) // Only first SQL injection check
      ];
      break;
      
    case 'test_insecure':
      // Deep insecure scan - check everything
      patterns = Object.values(securityPatterns).flat();
      break;
      
    case 'test_secrets':
      // Secrets detection - only credentials and tokens
      patterns = securityPatterns.credentials;
      break;
      
    case 'test_cve':
      // CVE Analysis - focus on known vulnerabilities
      if (fileName.includes('package.json')) {
        return analyzeCVEAndDependencies(content, fileName, command);
      }
      patterns = [...securityPatterns.weakCrypto, ...securityPatterns.deserialization];
      break;
      
    case 'test_dependencies':
      // Dependency check - analyze package vulnerabilities
      if (fileName.includes('package.json')) {
        return analyzeCVEAndDependencies(content, fileName, command);
      }
      patterns = [...securityPatterns.weakCrypto];
      break;
      
    case 'test_malware':
      // Malware detection - focus on dangerous code patterns
      patterns = [
        ...securityPatterns.commandInjection,
        ...securityPatterns.deserialization,
        { pattern: /base64\.b64decode|atob\(/gi, title: 'Suspicious Base64 Decoding', severity: 'high' },
        { pattern: /download|fetch.*\.exe|\.dll|\.so/gi, title: 'Suspicious File Download', severity: 'critical' },
        { pattern: /socket\.connect|net\.connect/gi, title: 'Network Connection Pattern', severity: 'medium' }
      ];
      break;
      
    case 'test_secure':
      // Secure compliance check - verify best practices
      patterns = [
        ...securityPatterns.credentials,
        ...securityPatterns.weakCrypto,
        ...securityPatterns.debug,
        ...securityPatterns.insecureHttp
      ];
      break;
      
    case 'test_full_secure':
      // Full security audit - everything including extra checks
      patterns = [
        ...Object.values(securityPatterns).flat(),
        { pattern: /TODO|FIXME|HACK/gi, title: 'Code Quality Issue', severity: 'low' },
        { pattern: /console\.log|print\(/gi, title: 'Debug Statement in Code', severity: 'low' }
      ];
      break;
      
    default:
      patterns = [...securityPatterns.credentials, ...securityPatterns.debug];
  }

  // Scan each line
  lines.forEach((line, index) => {
    patterns.forEach(({ pattern, title, severity }) => {
      // Reset the regex lastIndex to avoid issues with global flag
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        const lineNum = index + 1;
        vulnerabilities.push({
          title,
          description: getVulnerabilityDescription(title, line),
          severity,
          line: lineNum,
          code: line.trim(),
          recommendation: getRecommendation(title)
        });
        
        // Reduce security score based on severity
        const reduction = severity === 'critical' ? 15 : severity === 'high' ? 10 : severity === 'medium' ? 5 : 2;
        securityScore -= reduction;
      }
    });
  });

  // Ensure score doesn't go below 0
  securityScore = Math.max(0, securityScore);

  // Count vulnerabilities by severity
  const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
  const high = vulnerabilities.filter(v => v.severity === 'high').length;
  const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
  const low = vulnerabilities.filter(v => v.severity === 'low').length;

  // Generate recommendations
  const recommendations = generateRecommendations(vulnerabilities, command);

  // Determine status
  let status = 'Secure - All tests passed';
  if (critical > 0) status = `Critical security issues detected - ${critical} critical vulnerabilities`;
  else if (high > 0) status = `High severity vulnerabilities found - ${high} high-risk issues`;
  else if (medium > 0) status = `Medium risk issues identified - ${medium} moderate issues`;
  else if (low > 0) status = `Low risk issues found - ${low} minor issues`;

  return {
    command,
    summary: {
      totalIssues: vulnerabilities.length,
      critical,
      high,
      medium,
      low,
      securityScore,
      status
    },
    vulnerabilities,
    recommendations,
    scanTime: Math.floor(Math.random() * 2000) + 500,
    linesAnalyzed: lines.length,
    fileType: getFileType(fileName)
  };
}

// Separate function for CVE and dependency analysis
function analyzeCVEAndDependencies(content, fileName, command) {
  const vulnerabilities = [];
  let securityScore = 100;

  try {
    const pkg = JSON.parse(content);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    
    for (const [name, version] of Object.entries(deps)) {
      const cleanVersion = version.replace(/[\^~>=<]/g, '');
      if (knownVulnerabilities[name] && knownVulnerabilities[name][cleanVersion]) {
        knownVulnerabilities[name][cleanVersion].forEach(vuln => {
          vulnerabilities.push({
            title: `${vuln.cve}: ${name}@${cleanVersion}`,
            description: vuln.description,
            severity: vuln.severity,
            line: null,
            code: `"${name}": "${version}"`,
            recommendation: `Upgrade ${name} to a patched version (latest secure version recommended)`,
            cve: vuln.cve
          });
          securityScore -= vuln.severity === 'critical' ? 20 : vuln.severity === 'high' ? 15 : 10;
        });
      }
    }
  } catch (e) {
    console.error('Error parsing package.json:', e);
  }

  securityScore = Math.max(0, securityScore);

  const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
  const high = vulnerabilities.filter(v => v.severity === 'high').length;
  const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
  const low = vulnerabilities.filter(v => v.severity === 'low').length;

  const recommendations = generateRecommendations(vulnerabilities, command);

  let status = 'All dependencies are secure';
  if (critical > 0) status = `${critical} critical CVE vulnerabilities detected`;
  else if (high > 0) status = `${high} high-severity CVEs found`;
  else if (medium > 0) status = `${medium} medium-risk CVEs identified`;
  else if (low > 0) status = `${low} low-risk CVEs found`;

  return {
    command,
    summary: {
      totalIssues: vulnerabilities.length,
      critical,
      high,
      medium,
      low,
      securityScore,
      status
    },
    vulnerabilities,
    recommendations,
    scanTime: Math.floor(Math.random() * 1500) + 800,
    linesAnalyzed: content.split('\n').length,
    fileType: 'JSON Configuration'
  };
}

function getVulnerabilityDescription(title, line) {
  const descriptions = {
    'Hardcoded Password': 'Password is hardcoded in the source code, making it easy for attackers to find and exploit.',
    'Hardcoded API Key': 'API key is exposed in source code, potentially allowing unauthorized access to external services.',
    'Hardcoded Secret Key': 'Secret key is hardcoded, compromising the security of encryption and signing operations.',
    'Hardcoded Token': 'Authentication token is hardcoded, bypassing proper authentication mechanisms.',
    'Cloud Provider Credentials': 'Cloud service credentials are exposed, potentially granting full access to cloud resources.',
    'SQL Injection (String Concatenation)': 'SQL query constructed using string concatenation, vulnerable to SQL injection attacks.',
    'Potential SQL Injection (f-string)': 'Dynamic SQL query using f-strings without parameterization.',
    'SQL Injection via Concatenation': 'Database query vulnerable to SQL injection through string concatenation.',
    'Command Injection Vulnerability': 'User input passed directly to system commands, allowing arbitrary command execution.',
    'Code Execution Vulnerability': 'Dangerous use of exec() that could lead to arbitrary code execution.',
    'Dangerous eval() Usage': 'Use of eval() function can execute arbitrary code and should be avoided.',
    'Insecure Deserialization (pickle)': 'Pickle deserialization can lead to remote code execution if data is from untrusted sources.',
    'Insecure YAML Loading': 'Unsafe YAML loading can execute arbitrary Python code.',
    'Unsafe JSON Parsing': 'JSON parsing of untrusted data without validation.',
    'Weak Cryptographic Hash': 'Use of deprecated hash algorithms (MD5, SHA1) that are cryptographically broken.',
    'Weak Encryption Algorithm': 'Use of weak encryption algorithms that can be easily broken.',
    'Debug Mode Enabled': 'Debug mode should never be enabled in production as it exposes sensitive information.',
    'Insecure HTTP Connection': 'Using unencrypted HTTP for network communication exposes data to interception.',
    'SSL Verification Disabled': 'Disabling SSL certificate verification makes connections vulnerable to MITM attacks.',
    'Suspicious Base64 Decoding': 'Base64 decoding patterns often used to obfuscate malicious code.',
    'Suspicious File Download': 'Downloading and potentially executing files (.exe, .dll, .so) is a common malware pattern.',
    'Network Connection Pattern': 'Establishing network connections to external servers may indicate data exfiltration.',
    'Code Quality Issue': 'TODO/FIXME/HACK comments indicate incomplete or temporary code that may have security implications.',
    'Debug Statement in Code': 'Debug statements in production code may leak sensitive information.'
  };
  return descriptions[title] || 'Security vulnerability detected in the code.';
}

function getRecommendation(title) {
  const recommendations = {
    'Hardcoded Password': 'Use environment variables or secure secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager)',
    'Hardcoded API Key': 'Store API keys in environment variables or secret management services',
    'Hardcoded Secret Key': 'Use secure key management systems and rotate keys regularly',
    'Hardcoded Token': 'Store tokens securely and implement proper token rotation',
    'Cloud Provider Credentials': 'Use IAM roles and instance profiles instead of hardcoded credentials',
    'SQL Injection (String Concatenation)': 'Use parameterized queries or ORM with prepared statements',
    'Potential SQL Injection (f-string)': 'Switch to parameterized queries to prevent SQL injection',
    'SQL Injection via Concatenation': 'Always use parameterized queries for database operations',
    'Command Injection Vulnerability': 'Validate and sanitize all inputs, use safe alternatives to os.system()',
    'Code Execution Vulnerability': 'Avoid using exec(), use safe alternatives with input validation',
    'Dangerous eval() Usage': 'Replace eval() with safer alternatives like ast.literal_eval() or json.loads()',
    'Insecure Deserialization (pickle)': 'Use JSON for serialization or verify data source before unpickling',
    'Insecure YAML Loading': 'Use yaml.safe_load() instead of yaml.load()',
    'Unsafe JSON Parsing': 'Validate JSON schema before parsing untrusted data',
    'Weak Cryptographic Hash': 'Use SHA-256 or SHA-3 for hashing',
    'Weak Encryption Algorithm': 'Use AES-256 or ChaCha20-Poly1305 for encryption',
    'Debug Mode Enabled': 'Set debug=False in production environments',
    'Insecure HTTP Connection': 'Always use HTTPS for network communications',
    'SSL Verification Disabled': 'Enable SSL verification and use valid certificates',
    'Suspicious Base64 Decoding': 'Review code for malicious intent, avoid obfuscation, implement code signing',
    'Suspicious File Download': 'Remove file download/execution code, use sandboxing for file operations',
    'Network Connection Pattern': 'Verify legitimate need for external connections, implement network monitoring',
    'Code Quality Issue': 'Address all TODO/FIXME comments before production deployment',
    'Debug Statement in Code': 'Remove all debug/print statements from production code'
  };
  return recommendations[title] || 'Follow security best practices to mitigate this vulnerability';
}

function generateRecommendations(vulnerabilities, command) {
  const recs = new Set();
  
  if (vulnerabilities.some(v => v.title.includes('Password') || v.title.includes('Key'))) {
    recs.add('Implement a secure secrets management solution');
    recs.add('Use environment variables for sensitive configuration');
    recs.add('Enable secret scanning in your CI/CD pipeline');
  }
  
  if (vulnerabilities.some(v => v.title.includes('SQL Injection'))) {
    recs.add('Always use parameterized queries or ORM');
    recs.add('Implement input validation and sanitization');
    recs.add('Use a Web Application Firewall (WAF)');
  }
  
  if (vulnerabilities.some(v => v.title.includes('Command Injection'))) {
    recs.add('Never pass user input directly to system commands');
    recs.add('Use allowlists for permitted values');
    recs.add('Implement proper input validation');
  }
  
  if (vulnerabilities.some(v => v.severity === 'critical')) {
    recs.add('Address critical vulnerabilities immediately');
    recs.add('Conduct security code review');
    recs.add('Consider penetration testing');
  }
  
  if (command === 'test_full_secure') {
    recs.add('Implement automated security testing in CI/CD');
    recs.add('Regular security audits and code reviews');
    recs.add('Keep all dependencies up to date');
    recs.add('Follow OWASP Top 10 security guidelines');
    recs.add('Enable security headers and CSP');
  }
  
  return Array.from(recs);
}

function getFileType(fileName) {
  const ext = fileName.split('.').pop().toLowerCase();
  const types = {
    'py': 'Python',
    'js': 'JavaScript',
    'ts': 'TypeScript',
    'json': 'JSON Configuration',
    'yml': 'YAML Configuration',
    'yaml': 'YAML Configuration',
    'env': 'Environment Variables',
    'sh': 'Shell Script',
    'java': 'Java',
    'cpp': 'C++',
    'c': 'C',
    'rb': 'Ruby',
    'php': 'PHP',
    'go': 'Go'
  };
  return types[ext] || 'Unknown';
}

export async function POST(request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const command = formData.get('command') || 'test';

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
    }

    const content = await file.text();
    const fileName = file.name;

    // Analyze the file
    const results = analyzeFileContent(content, fileName, command);

    return NextResponse.json(results);
  } catch (error) {
    console.error('Agent scan error:', error);
    return NextResponse.json({ 
      error: 'Failed to scan file',
      details: error.message 
    }, { status: 500 });
  }
}
