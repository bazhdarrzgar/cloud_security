import { NextResponse } from 'next/server';

// Security patterns to detect in code
const securityPatterns = {
  javascript: [
    {
      pattern: /eval\s*\(/gi,
      title: 'Dangerous eval() Usage',
      description: 'Using eval() can lead to code injection vulnerabilities',
      severity: 'critical',
      category: 'Security',
      impact: 'Attackers could execute arbitrary code in your application',
      remediation: 'Avoid using eval(). Use JSON.parse() for JSON data or safer alternatives',
      cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
      references: ['https://owasp.org/www-community/attacks/Code_Injection']
    },
    {
      pattern: /innerHTML\s*=/gi,
      title: 'Potential XSS via innerHTML',
      description: 'Setting innerHTML with unsanitized user input can lead to XSS attacks',
      severity: 'high',
      category: 'Security',
      impact: 'Attackers could inject malicious scripts that execute in users\' browsers',
      remediation: 'Use textContent or sanitize HTML input with DOMPurify library',
      cwe: 'CWE-79: Cross-site Scripting (XSS)',
      references: ['https://owasp.org/www-community/attacks/xss/']
    },
    {
      pattern: /document\.write\s*\(/gi,
      title: 'Unsafe document.write() Usage',
      description: 'document.write() can be exploited for XSS attacks',
      severity: 'high',
      category: 'Security',
      impact: 'Potential cross-site scripting vulnerability',
      remediation: 'Use modern DOM manipulation methods like appendChild() or insertAdjacentHTML()',
      cwe: 'CWE-79: Cross-site Scripting (XSS)'
    },
    {
      pattern: /console\.(log|error|warn|debug|info)\s*\(/gi,
      title: 'Console Statement in Production',
      description: 'Console statements can leak sensitive information in production',
      severity: 'low',
      category: 'Code Quality',
      impact: 'Sensitive data might be exposed in browser console',
      remediation: 'Remove console statements before deploying to production or use a logger',
      cwe: 'CWE-532: Information Exposure Through Log Files'
    },
    {
      pattern: /dangerouslySetInnerHTML/gi,
      title: 'React dangerouslySetInnerHTML Usage',
      description: 'Using dangerouslySetInnerHTML without sanitization can lead to XSS',
      severity: 'high',
      category: 'Security',
      impact: 'Cross-site scripting vulnerability in React application',
      remediation: 'Sanitize HTML content using DOMPurify before rendering',
      cwe: 'CWE-79: Cross-site Scripting (XSS)'
    }
  ],
  python: [
    {
      pattern: /eval\s*\(/gi,
      title: 'Dangerous eval() Function',
      description: 'Using eval() with untrusted input allows arbitrary code execution',
      severity: 'critical',
      category: 'Security',
      impact: 'Complete system compromise possible through code injection',
      remediation: 'Use ast.literal_eval() for safe evaluation or avoid eval() entirely',
      cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
      references: ['https://docs.python.org/3/library/ast.html#ast.literal_eval']
    },
    {
      pattern: /exec\s*\(/gi,
      title: 'Dangerous exec() Function',
      description: 'exec() can execute arbitrary Python code, leading to code injection',
      severity: 'critical',
      category: 'Security',
      impact: 'Arbitrary code execution vulnerability',
      remediation: 'Avoid using exec(). Redesign code to use safer alternatives',
      cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code'
    },
    {
      pattern: /pickle\.loads?\s*\(/gi,
      title: 'Insecure Deserialization with Pickle',
      description: 'Pickle can execute arbitrary code during deserialization',
      severity: 'critical',
      category: 'Security',
      impact: 'Remote code execution through malicious pickle data',
      remediation: 'Use JSON for data serialization or validate pickle data source',
      cwe: 'CWE-502: Deserialization of Untrusted Data',
      references: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data']
    },
    {
      pattern: /subprocess\.call\s*\([^)]*shell\s*=\s*True/gi,
      title: 'Shell Injection Vulnerability',
      description: 'Using shell=True with subprocess can lead to command injection',
      severity: 'critical',
      category: 'Security',
      impact: 'Attackers can execute arbitrary system commands',
      remediation: 'Remove shell=True and pass command as a list instead',
      cwe: 'CWE-78: OS Command Injection',
      references: ['https://owasp.org/www-community/attacks/Command_Injection']
    },
    {
      pattern: /\.format\s*\([^)]*\)/gi,
      title: 'Potential SQL Injection in String Formatting',
      description: 'Using .format() for SQL queries can lead to SQL injection',
      severity: 'high',
      category: 'Security',
      impact: 'Database compromise through SQL injection attacks',
      remediation: 'Use parameterized queries or ORM methods instead',
      cwe: 'CWE-89: SQL Injection'
    },
    {
      pattern: /assert\s+/gi,
      title: 'Assert Statement in Production Code',
      description: 'Assert statements are removed when Python runs in optimized mode',
      severity: 'medium',
      category: 'Code Quality',
      impact: 'Security checks might be bypassed in production',
      remediation: 'Use proper error handling with if statements and raise exceptions',
      cwe: 'CWE-617: Reachable Assertion'
    }
  ],
  json: [
    {
      pattern: /password|passwd|pwd/gi,
      title: 'Possible Hardcoded Password',
      description: 'Configuration file contains password-related fields',
      severity: 'high',
      category: 'Security',
      impact: 'Credentials might be exposed in version control',
      remediation: 'Use environment variables for sensitive data',
      cwe: 'CWE-798: Use of Hard-coded Credentials'
    },
    {
      pattern: /api[_-]?key|apikey|secret[_-]?key|access[_-]?token/gi,
      title: 'Possible API Key or Secret',
      description: 'Configuration file may contain API keys or secrets',
      severity: 'high',
      category: 'Security',
      impact: 'API keys could be exposed leading to unauthorized access',
      remediation: 'Move secrets to environment variables or secret management system',
      cwe: 'CWE-798: Use of Hard-coded Credentials'
    },
    {
      pattern: /"debug"\s*:\s*true/gi,
      title: 'Debug Mode Enabled',
      description: 'Debug mode is enabled which can expose sensitive information',
      severity: 'medium',
      category: 'Security',
      impact: 'Detailed error messages might leak system information',
      remediation: 'Set debug to false in production environments',
      cwe: 'CWE-489: Active Debug Code'
    }
  ],
  yaml: [
    {
      pattern: /password|passwd|pwd|secret|token|key/gi,
      title: 'Sensitive Data in YAML Config',
      description: 'YAML file contains sensitive credential fields',
      severity: 'high',
      category: 'Security',
      impact: 'Credentials might be exposed in configuration files',
      remediation: 'Use environment variables or secret management systems',
      cwe: 'CWE-798: Use of Hard-coded Credentials'
    }
  ],
  env: [
    {
      pattern: /[A-Z_]+=.+/g,
      title: 'Environment Variable Defined',
      description: 'Ensure .env files are not committed to version control',
      severity: 'medium',
      category: 'Security',
      impact: 'Sensitive configuration could be exposed if committed',
      remediation: 'Add .env to .gitignore and use .env.example for documentation',
      cwe: 'CWE-540: Information Exposure Through Source Code'
    }
  ]
};

// Code quality patterns
const qualityPatterns = {
  javascript: [
    {
      pattern: /var\s+\w+/gi,
      title: 'Use of var keyword',
      description: 'var has function scope which can lead to bugs. Use let or const instead',
      severity: 'low',
      category: 'Code Quality',
      impact: 'Potential scope-related bugs',
      remediation: 'Replace var with let or const for better scoping'
    },
    {
      pattern: /==(?!=)/g,
      title: 'Loose Equality Comparison',
      description: 'Using == can lead to unexpected type coercion',
      severity: 'low',
      category: 'Code Quality',
      impact: 'Unexpected behavior due to type coercion',
      remediation: 'Use strict equality === instead'
    }
  ],
  python: [
    {
      pattern: /except\s*:/gi,
      title: 'Bare except Clause',
      description: 'Catching all exceptions without specificity can hide bugs',
      severity: 'medium',
      category: 'Code Quality',
      impact: 'Errors might be silently caught and ignored',
      remediation: 'Catch specific exception types like except ValueError:'
    },
    {
      pattern: /print\s*\(/gi,
      title: 'Print Statement in Code',
      description: 'Print statements should be replaced with proper logging',
      severity: 'low',
      category: 'Code Quality',
      impact: 'Debugging output in production code',
      remediation: 'Use logging module for better control over output'
    }
  ]
};

function detectFileType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  if (['js', 'jsx', 'ts', 'tsx'].includes(ext)) return 'javascript';
  if (ext === 'py') return 'python';
  if (ext === 'json') return 'json';
  if (['yaml', 'yml'].includes(ext)) return 'yaml';
  if (ext === 'env') return 'env';
  return 'unknown';
}

function scanFileContent(filename, content) {
  const fileType = detectFileType(filename);
  const findings = [];
  
  if (!securityPatterns[fileType] && !qualityPatterns[fileType]) {
    return findings;
  }

  // Scan for security issues
  const secPatterns = securityPatterns[fileType] || [];
  secPatterns.forEach(pattern => {
    const matches = content.matchAll(pattern.pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = content.split('\n')[lineNumber - 1];
      
      findings.push({
        ...pattern,
        file: filename,
        line: lineNumber,
        code: lineContent?.trim(),
        matchedText: match[0]
      });
    }
  });

  // Scan for code quality issues
  const qualPatterns = qualityPatterns[fileType] || [];
  qualPatterns.forEach(pattern => {
    const matches = content.matchAll(pattern.pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = content.split('\n')[lineNumber - 1];
      
      findings.push({
        ...pattern,
        file: filename,
        line: lineNumber,
        code: lineContent?.trim(),
        matchedText: match[0]
      });
    }
  });

  return findings;
}

export async function POST(request) {
  try {
    const { files } = await request.json();
    
    if (!files || files.length === 0) {
      return NextResponse.json(
        { error: 'No files provided' },
        { status: 400 }
      );
    }

    // Simulate scanning delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    let allFindings = [];
    
    // Scan each file
    files.forEach(file => {
      const findings = scanFileContent(file.name, file.content);
      allFindings = [...allFindings, ...findings];
    });

    // Calculate statistics
    const stats = {
      totalIssues: allFindings.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      securityIssues: allFindings.filter(f => f.category === 'Security').length,
      qualityIssues: allFindings.filter(f => f.category === 'Code Quality').length,
      filesScanned: files.length
    };

    // Sort findings by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return NextResponse.json({
      findings: allFindings,
      stats,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error scanning files:', error);
    return NextResponse.json(
      { error: 'Failed to scan files' },
      { status: 500 }
    );
  }
}
