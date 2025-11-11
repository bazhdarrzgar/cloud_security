import { NextResponse } from 'next/server';

// Global environment store
let globalEnvironment = null;

// Simulated cloud environment with vulnerabilities
function generateCloudEnvironment() {
  return {
    vms: [
      { id: 'vm-001', name: 'web-server-prod', status: 'running', os: 'Ubuntu 20.04', vulnerabilities: ['open-ssh-port', 'weak-password', 'outdated-packages', 'missing-security-patches', 'insecure-ssl'], publicIP: '54.123.45.67', region: 'us-east-1', instanceType: 't3.medium', launchedAt: '2024-03-15' },
      { id: 'vm-002', name: 'db-server', status: 'running', os: 'CentOS 7', vulnerabilities: ['default-password', 'unpatched-kernel', 'no-encryption', 'excessive-privileges'], publicIP: '54.123.45.68', region: 'us-east-1', instanceType: 't3.large', launchedAt: '2024-01-20' },
      { id: 'vm-003', name: 'app-server', status: 'running', os: 'Ubuntu 22.04', vulnerabilities: ['exposed-admin-panel', 'weak-firewall', 'unencrypted-volumes'], publicIP: '54.123.45.69', region: 'us-west-2', instanceType: 't3.xlarge', launchedAt: '2024-05-10' },
      { id: 'vm-004', name: 'analytics-worker', status: 'running', os: 'Debian 11', vulnerabilities: ['suspicious-process', 'memory-threat', 'rootkit-detected', 'unauthorized-ssh-keys'], publicIP: null, region: 'eu-west-1', instanceType: 't3.small', launchedAt: '2024-02-28' },
      { id: 'vm-005', name: 'legacy-server', status: 'running', os: 'Ubuntu 18.04', vulnerabilities: ['eol-operating-system', 'multiple-cves', 'no-antivirus', 'exposed-services'], publicIP: '54.123.45.70', region: 'us-east-1', instanceType: 't2.micro', launchedAt: '2023-11-05' }
    ],
    databases: [
      { id: 'db-001', name: 'users-db', type: 'PostgreSQL', version: '12.3', vulnerabilities: ['weak-password', 'public-access', 'no-encryption', 'no-backup', 'sql-injection-risk'], encryption: false, connections: 245 },
      { id: 'db-002', name: 'analytics-db', type: 'MongoDB', version: '4.2', vulnerabilities: ['default-credentials', 'outdated-version', 'no-audit-logs'], encryption: false, connections: 89 },
      { id: 'db-003', name: 'cache-db', type: 'Redis', version: '5.0', vulnerabilities: ['no-authentication', 'public-endpoint', 'no-encryption'], encryption: false, connections: 512 },
      { id: 'db-004', name: 'payments-db', type: 'MySQL', version: '5.7', vulnerabilities: ['weak-authentication', 'no-ssl', 'exposed-port', 'privileged-accounts'], encryption: false, connections: 156 }
    ],
    storage: [
      { id: 's3-001', name: 'user-uploads', type: 'S3 Bucket', public: true, encryption: false, vulnerabilities: ['public-access', 'no-encryption', 'no-versioning', 'no-logging'], objects: 15420, size: '2.4 TB' },
      { id: 's3-002', name: 'backup-data', type: 'S3 Bucket', public: false, encryption: false, vulnerabilities: ['no-encryption', 'weak-acl', 'no-lifecycle-policy'], objects: 8932, size: '5.8 TB' },
      { id: 's3-003', name: 'logs-bucket', type: 'S3 Bucket', public: true, vulnerabilities: ['public-access', 'sensitive-data-exposed', 'no-retention-policy'], objects: 45120, size: '890 GB' },
      { id: 's3-004', name: 'config-files', type: 'S3 Bucket', public: false, vulnerabilities: ['hardcoded-secrets', 'no-encryption', 'overpermissive-policy'], objects: 234, size: '120 MB' }
    ],
    iam: [
      { id: 'iam-001', name: 'admin-role', permissions: ['*:*:*'], vulnerabilities: ['overly-permissive', 'no-mfa', 'unused-permissions'], users: 3, lastUsed: '2 hours ago' },
      { id: 'iam-002', name: 'developer-role', permissions: ['s3:*', 'ec2:*', 'rds:*'], vulnerabilities: ['excessive-permissions', 'no-session-duration'], users: 12, lastUsed: '5 minutes ago' },
      { id: 'iam-003', name: 'service-account', permissions: ['dynamodb:*'], vulnerabilities: ['exposed-api-key', 'no-rotation', 'permanent-credentials'], users: 1, lastUsed: '1 day ago' },
      { id: 'iam-004', name: 'ci-cd-role', permissions: ['iam:*', 'lambda:*'], vulnerabilities: ['privilege-escalation-risk', 'cross-account-access'], users: 2, lastUsed: '30 minutes ago' }
    ],
    network: [
      { id: 'sg-001', name: 'web-security-group', rules: [{ port: 22, source: '0.0.0.0/0' }, { port: 80, source: '0.0.0.0/0' }, { port: 443, source: '0.0.0.0/0' }, { port: 8080, source: '0.0.0.0/0' }], vulnerabilities: ['open-ssh', 'permissive-rules', 'unrestricted-egress'], attachedResources: 5 },
      { id: 'sg-002', name: 'db-security-group', rules: [{ port: 5432, source: '0.0.0.0/0' }, { port: 3306, source: '0.0.0.0/0' }, { port: 27017, source: '0.0.0.0/0' }], vulnerabilities: ['open-database-ports', 'public-access', 'no-traffic-filtering'], attachedResources: 4 },
      { id: 'sg-003', name: 'app-security-group', rules: [{ port: 8080, source: '0.0.0.0/0' }, { port: 3000, source: '0.0.0.0/0' }], vulnerabilities: ['weak-firewall', 'exposed-internal-ports'], attachedResources: 3 }
    ]
  };
}

// Calculate Zero Trust Security Score
function calculateZeroTrustScore(findings, environment) {
  // Identity Verification Score
  const mfaIssues = findings.filter(f => f.vulnerability === 'no-mfa').length;
  const authIssues = findings.filter(f => ['weak-password', 'default-password', 'weak-authentication'].includes(f.vulnerability)).length;
  const identityVerification = Math.max(0, 100 - (mfaIssues * 15 + authIssues * 10));
  
  // Device Trust Score
  const deviceIssues = findings.filter(f => ['no-antivirus', 'rootkit-detected', 'eol-operating-system'].includes(f.vulnerability)).length;
  const patchIssues = findings.filter(f => ['outdated-packages', 'missing-security-patches', 'unpatched-kernel'].includes(f.vulnerability)).length;
  const deviceTrust = Math.max(0, 100 - (deviceIssues * 20 + patchIssues * 10));
  
  // Network Segmentation Score
  const networkIssues = findings.filter(f => ['open-ssh', 'open-database-ports', 'exposed-admin-panel', 'public-endpoint'].includes(f.vulnerability)).length;
  const firewallIssues = findings.filter(f => ['weak-firewall', 'permissive-rules', 'no-traffic-filtering'].includes(f.vulnerability)).length;
  const networkSegmentation = Math.max(0, 100 - (networkIssues * 12 + firewallIssues * 8));
  
  // Least Privilege Access Score
  const privilegeIssues = findings.filter(f => ['overly-permissive', 'excessive-permissions', 'excessive-privileges'].includes(f.vulnerability)).length;
  const accessIssues = findings.filter(f => ['unused-permissions', 'privilege-escalation-risk'].includes(f.vulnerability)).length;
  const leastPrivilege = Math.max(0, 100 - (privilegeIssues * 15 + accessIssues * 5));
  
  // Overall Score
  const score = Math.round((identityVerification + deviceTrust + networkSegmentation + leastPrivilege) / 4);
  
  const zeroTrustFindings = findings.filter(f => 
    ['no-mfa', 'weak-password', 'default-password', 'weak-authentication', 
     'no-antivirus', 'rootkit-detected', 'eol-operating-system',
     'outdated-packages', 'missing-security-patches', 'unpatched-kernel',
     'open-ssh', 'open-database-ports', 'exposed-admin-panel', 'public-endpoint',
     'weak-firewall', 'permissive-rules', 'no-traffic-filtering',
     'overly-permissive', 'excessive-permissions', 'excessive-privileges',
     'unused-permissions', 'privilege-escalation-risk'].includes(f.vulnerability)
  );
  
  return {
    score,
    identityVerification,
    deviceTrust,
    networkSegmentation,
    leastPrivilege,
    findings: zeroTrustFindings.map(f => ({
      category: getZeroTrustCategory(f.vulnerability),
      resource: f.resourceName,
      issue: f.vulnerabilityTitle,
      severity: f.severity
    }))
  };
}

function getZeroTrustCategory(vuln) {
  if (['no-mfa', 'weak-password', 'default-password', 'weak-authentication'].includes(vuln)) {
    return 'Identity Verification';
  } else if (['no-antivirus', 'rootkit-detected', 'eol-operating-system', 'outdated-packages', 'missing-security-patches', 'unpatched-kernel'].includes(vuln)) {
    return 'Device Trust';
  } else if (['open-ssh', 'open-database-ports', 'exposed-admin-panel', 'public-endpoint', 'weak-firewall', 'permissive-rules', 'no-traffic-filtering'].includes(vuln)) {
    return 'Network Segmentation';
  } else {
    return 'Least Privilege Access';
  }
}

// Generate Anomaly Detections
function generateAnomalyDetections(environment) {
  const anomalies = [];
  
  // Unusual Access Patterns
  const unusualAccessCount = Math.floor(Math.random() * 5) + 3;
  anomalies.push({
    name: 'Unusual Access Patterns',
    description: 'Detected access from unusual locations and times',
    count: unusualAccessCount,
    severity: 'high',
    examples: [
      'Database access from IP 45.67.89.12 (Russia) at 3:42 AM',
      'Admin login from new device without MFA',
      'Bulk data download outside business hours'
    ]
  });
  
  // Privilege Escalation Attempts
  const escalationCount = Math.floor(Math.random() * 3) + 2;
  anomalies.push({
    name: 'Privilege Escalation Attempts',
    description: 'Suspicious attempts to gain elevated permissions',
    count: escalationCount,
    severity: 'high',
    examples: [
      'User attempting to modify IAM policies',
      'Service account accessing admin endpoints',
      'Multiple sudo failures on production server'
    ]
  });
  
  // Data Exfiltration Indicators
  const exfiltrationCount = Math.floor(Math.random() * 4) + 1;
  anomalies.push({
    name: 'Data Exfiltration Indicators',
    description: 'Unusual data transfer patterns detected',
    count: exfiltrationCount,
    severity: 'high',
    examples: [
      'Outbound traffic spike to unknown IP: 234.5 GB',
      'Database queries returning entire tables',
      'Compressed archive created in /tmp directory'
    ]
  });
  
  // Lateral Movement Detection
  const lateralCount = Math.floor(Math.random() * 3) + 1;
  anomalies.push({
    name: 'Lateral Movement',
    description: 'Potential attacker movement between systems',
    count: lateralCount,
    severity: 'medium',
    examples: [
      'SSH connections between unrelated systems',
      'Service account accessing multiple resources',
      'Port scanning activity detected internally'
    ]
  });
  
  const total = anomalies.reduce((sum, a) => sum + a.count, 0);
  const critical = anomalies.filter(a => a.severity === 'high').reduce((sum, a) => sum + a.count, 0);
  
  return {
    total,
    critical,
    types: anomalies,
    lastDetected: new Date().toISOString(),
    mlModelVersion: '2.4.1'
  };
}

// Generate Runtime Threats
function generateRuntimeThreats(environment) {
  const threats = [];
  
  // Malicious Process Detection
  const maliciousProcessCount = Math.floor(Math.random() * 3) + 2;
  threats.push({
    name: 'Malicious Process Detection',
    description: 'Suspicious processes running in memory',
    count: maliciousProcessCount,
    risk: 'critical',
    examples: [
      'cryptominer.exe consuming 95% CPU on vm-004',
      'Unauthorized network scanner detected',
      'Backdoor process listening on port 4444'
    ]
  });
  
  // Memory Injection Attacks
  const memoryAttackCount = Math.floor(Math.random() * 2) + 1;
  threats.push({
    name: 'Memory Injection Attacks',
    description: 'Code injection attempts in running processes',
    count: memoryAttackCount,
    risk: 'critical',
    examples: [
      'DLL injection detected in system process',
      'Process hollowing attempt blocked',
      'Reflective loading of malicious payload'
    ]
  });
  
  // Container Escape Attempts
  const containerEscapeCount = Math.floor(Math.random() * 2) + 1;
  threats.push({
    name: 'Container Escape Attempts',
    description: 'Attempts to break out of container isolation',
    count: containerEscapeCount,
    risk: 'high',
    examples: [
      'Privileged container accessing host filesystem',
      'Kernel exploit attempt from container',
      'Suspicious mount operations detected'
    ]
  });
  
  // File Integrity Violations
  const fileIntegrityCount = Math.floor(Math.random() * 4) + 2;
  threats.push({
    name: 'File Integrity Violations',
    description: 'Unauthorized file modifications detected',
    count: fileIntegrityCount,
    risk: 'high',
    examples: [
      'System binary modified: /usr/bin/sudo',
      'Cron job added by unknown user',
      'Shadow file accessed unexpectedly'
    ]
  });
  
  // Network Anomalies
  const networkAnomalyCount = Math.floor(Math.random() * 5) + 3;
  threats.push({
    name: 'Network Anomalies',
    description: 'Suspicious network connections and traffic',
    count: networkAnomalyCount,
    risk: 'medium',
    examples: [
      'Connection to known C2 server: 185.220.101.42',
      'DNS tunneling activity detected',
      'Unusual outbound TOR traffic'
    ]
  });
  
  const activeThreats = threats.reduce((sum, t) => sum + t.count, 0);
  const blocked = Math.floor(activeThreats * 0.7); // 70% blocked
  
  return {
    activeThreats,
    blocked,
    categories: threats,
    monitoredProcesses: environment.vms.length * 45 + Math.floor(Math.random() * 50),
    monitoredResources: environment.vms.length + environment.databases.length,
    lastScan: new Date().toISOString()
  };
}

// Security test types
const securityTests = [
  { id: 'config-scan', name: 'Configuration Scan', description: 'Detect insecure defaults and misconfigurations', agentBased: true, agentless: true },
  { id: 'vuln-check', name: 'Vulnerability Check', description: 'Scan for outdated packages and known CVEs', agentBased: true, agentless: true },
  { id: 'port-scan', name: 'Open Port Detection', description: 'Identify exposed services and ports', agentBased: true, agentless: true },
  { id: 'iam-audit', name: 'IAM Permission Audit', description: 'Check for over-permissive roles and policies', agentBased: true, agentless: true },
  { id: 'encryption', name: 'Encryption Check', description: 'Verify data encryption at rest and in transit', agentBased: true, agentless: true },
  { id: 'network-security', name: 'Network Security', description: 'Analyze firewall rules and network configurations', agentBased: true, agentless: true },
  { id: 'cis-benchmark', name: 'CIS Benchmark Compliance', description: 'Evaluate against CIS security standards', agentBased: true, agentless: false },
  { id: 'soc2', name: 'SOC2 Compliance', description: 'Check SOC2 requirements compliance', agentBased: true, agentless: true },
  { id: 'gdpr', name: 'GDPR Compliance', description: 'Verify GDPR data protection requirements', agentBased: true, agentless: false },
  { id: 'threat-detection', name: 'Threat Detection', description: 'Detect suspicious processes and network activity', agentBased: true, agentless: false },
  { id: 'zero-trust', name: 'Zero Trust Security', description: 'Evaluate zero trust security model implementation', agentBased: true, agentless: false },
  { id: 'anomaly-detection', name: 'Anomaly Detection', description: 'ML-based detection of unusual behavior patterns', agentBased: true, agentless: false },
  { id: 'runtime-protection', name: 'Runtime Protection', description: 'Real-time monitoring and threat prevention', agentBased: true, agentless: false }
];

// Simulate agent-based scanning
function runAgentBasedScan(environment, fileSystemChanges = []) {
  const findings = [];
  const startTime = Date.now();
  
  // Add file system change detections first
  fileSystemChanges.forEach((change, index) => {
    const isFolder = change.type.includes('folder');
    const isFile = change.type.includes('file');
    const isDeleted = change.type.includes('deleted');
    const isCreated = change.type.includes('created');
    const isModified = change.type.includes('modified');
    
    findings.push({
      resourceId: 'vm-windows-cloud-preview',
      resourceName: 'Windows Cloud Environment',
      resourceType: 'File System',
      severity: isDeleted ? 'high' : isCreated ? 'medium' : 'low',
      vulnerability: `file-system-${isFolder ? 'folder' : 'file'}-${isCreated ? 'created' : isDeleted ? 'deleted' : 'modified'}`,
      vulnerabilityTitle: `${isFolder ? 'Folder' : 'File'} ${isCreated ? 'Created' : isDeleted ? 'Deleted' : 'Modified'}: ${change.itemName}`,
      description: `Agent-based scan detected ${isFolder ? 'folder' : 'file'} ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} in the cloud environment. Item: "${change.itemName}" at location: ${change.path}`,
      testType: 'Real-time File System Monitoring (Agent)',
      detected: true,
      detectedBy: 'agent-based',
      cvss: isDeleted ? 7.5 : isCreated ? 5.5 : 4.0,
      cve: [],
      impact: `File system ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} detected via agent monitoring at ${change.timestamp}. ${isFolder ? 'Folder' : 'File'}: "${change.itemName}". ${isCreated ? 'New item was added to the system which may indicate installation of software, data upload, or configuration changes.' : isDeleted ? 'Item was removed which could indicate data cleanup, unauthorized deletion, or potential security incident.' : 'Item was modified which may indicate updates, configuration changes, or potential tampering.'}`,
      remediation: [
        `Verify that the ${isFolder ? 'folder' : 'file'} ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} was authorized and expected`,
        'Review access logs to identify the user or process responsible for this change',
        'Check if this change aligns with your change management policies',
        'Scan the affected area for any malicious content or unauthorized modifications',
        'Enable continuous file integrity monitoring (FIM) for critical directories',
        'Implement approval workflows for file system changes in production environments',
        'Review and update file system permissions to prevent unauthorized changes',
        'Set up alerts for suspicious file system activities'
      ],
      complianceImpact: [
        'SOC2 CC6.1 - Logical and Physical Access Controls',
        'SOC2 CC7.2 - System Monitoring',
        'ISO 27001 A.12.4.1 - Event Logging', 
        'ISO 27001 A.18.1.3 - Protection of Records',
        'NIST 800-53 AU-2 - Event Logging',
        'NIST 800-53 AU-6 - Audit Review',
        'NIST 800-53 CM-3 - Configuration Change Control',
        'PCI-DSS 10.2 - Implement automated audit trails',
        'GDPR Article 32 - Security of Processing'
      ],
      riskScore: isDeleted ? 75 : isCreated ? 55 : 40,
      resourceDetails: {
        itemType: isFolder ? 'Folder' : 'File',
        itemName: change.itemName,
        path: change.path,
        changeType: change.type,
        timestamp: change.timestamp,
        detectionMethod: 'Agent-based real-time monitoring'
      }
    });
  });
  
  // VMs - Agent can deeply inspect
  environment.vms.forEach(vm => {
    vm.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, vm);
      findings.push({
        resourceId: vm.id,
        resourceName: vm.name,
        resourceType: 'VM',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agent-based',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          os: vm.os,
          publicIP: vm.publicIP,
          region: vm.region,
          instanceType: vm.instanceType,
          launchedAt: vm.launchedAt
        }
      });
    });
  });
  
  // Databases
  environment.databases.forEach(db => {
    db.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, db);
      findings.push({
        resourceId: db.id,
        resourceName: db.name,
        resourceType: 'Database',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agent-based',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          type: db.type,
          version: db.version,
          encryption: db.encryption,
          connections: db.connections
        }
      });
    });
  });
  
  // Storage
  environment.storage.forEach(bucket => {
    bucket.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, bucket);
      findings.push({
        resourceId: bucket.id,
        resourceName: bucket.name,
        resourceType: 'Storage',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agent-based',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          public: bucket.public,
          encryption: bucket.encryption,
          objects: bucket.objects,
          size: bucket.size
        }
      });
    });
  });
  
  // IAM
  environment.iam.forEach(role => {
    role.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, role);
      findings.push({
        resourceId: role.id,
        resourceName: role.name,
        resourceType: 'IAM Role',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agent-based',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          permissions: role.permissions,
          users: role.users,
          lastUsed: role.lastUsed
        }
      });
    });
  });
  
  // Network
  environment.network.forEach(sg => {
    sg.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, sg);
      findings.push({
        resourceId: sg.id,
        resourceName: sg.name,
        resourceType: 'Security Group',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agent-based',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          rules: sg.rules,
          attachedResources: sg.attachedResources
        }
      });
    });
  });
  
  const scanTime = 18000 + Math.random() * 8000; // 18-26 seconds
  
  // Calculate Zero Trust Score
  const zeroTrustScore = calculateZeroTrustScore(findings, environment);
  
  // Generate Anomaly Detections
  const anomalyDetections = generateAnomalyDetections(environment);
  
  // Generate Runtime Threats
  const runtimeThreats = generateRuntimeThreats(environment);
  
  return {
    findings,
    stats: {
      totalResources: environment.vms.length + environment.databases.length + environment.storage.length + environment.iam.length + environment.network.length,
      vulnerabilitiesFound: findings.length,
      criticalIssues: findings.filter(f => f.severity === 'critical').length,
      highIssues: findings.filter(f => f.severity === 'high').length,
      mediumIssues: findings.filter(f => f.severity === 'medium').length,
      lowIssues: findings.filter(f => f.severity === 'low').length,
      scanTime: Math.round(scanTime),
      testsRun: securityTests.filter(t => t.agentBased).length,
      detectionRate: 95,
      avgRiskScore: Math.round(findings.reduce((sum, f) => sum + f.riskScore, 0) / findings.length)
    },
    zeroTrustScore,
    anomalyDetections,
    runtimeThreats
  };
}

// Simulate agentless scanning
function runAgentlessScan(environment, fileSystemChanges = []) {
  const findings = [];
  const startTime = Date.now();
  
  // Add file system change detections
  fileSystemChanges.forEach((change, index) => {
    const isFolder = change.type.includes('folder');
    const isFile = change.type.includes('file');
    const isDeleted = change.type.includes('deleted');
    const isCreated = change.type.includes('created');
    const isModified = change.type.includes('modified');
    
    findings.push({
      resourceId: 'vm-windows-cloud-preview',
      resourceName: 'Windows Cloud Environment',
      resourceType: 'File System',
      severity: isDeleted ? 'high' : isCreated ? 'medium' : 'low',
      vulnerability: `file-system-${isFolder ? 'folder' : 'file'}-${isCreated ? 'created' : isDeleted ? 'deleted' : 'modified'}`,
      vulnerabilityTitle: `${isFolder ? 'Folder' : 'File'} ${isCreated ? 'Created' : isDeleted ? 'Deleted' : 'Modified'}: ${change.itemName}`,
      description: `Agentless scan detected ${isFolder ? 'folder' : 'file'} ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} in the cloud environment. Item: "${change.itemName}" at location: ${change.path}`,
      testType: 'Real-time File System Monitoring',
      detected: true,
      detectedBy: 'agentless',
      cvss: isDeleted ? 7.5 : isCreated ? 5.5 : 4.0,
      cve: [],
      impact: `File system ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} detected via API monitoring at ${change.timestamp}. ${isFolder ? 'Folder' : 'File'}: "${change.itemName}". ${isCreated ? 'New item was added to the system which may indicate installation of software, data upload, or configuration changes.' : isDeleted ? 'Item was removed which could indicate data cleanup, unauthorized deletion, or potential security incident.' : 'Item was modified which may indicate updates, configuration changes, or potential tampering.'}`,
      remediation: [
        `Verify that the ${isFolder ? 'folder' : 'file'} ${isCreated ? 'creation' : isDeleted ? 'deletion' : 'modification'} was authorized and expected`,
        'Review access logs to identify the user or process responsible for this change',
        'Check if this change aligns with your change management policies',
        'Scan the affected area for any malicious content or unauthorized modifications',
        'Enable continuous file integrity monitoring (FIM) for critical directories',
        'Implement approval workflows for file system changes in production environments',
        'Review and update file system permissions to prevent unauthorized changes',
        'Set up alerts for suspicious file system activities'
      ],
      complianceImpact: [
        'SOC2 CC6.1 - Logical and Physical Access Controls',
        'SOC2 CC7.2 - System Monitoring',
        'ISO 27001 A.12.4.1 - Event Logging', 
        'ISO 27001 A.18.1.3 - Protection of Records',
        'NIST 800-53 AU-2 - Event Logging',
        'NIST 800-53 AU-6 - Audit Review',
        'NIST 800-53 CM-3 - Configuration Change Control',
        'PCI-DSS 10.2 - Implement automated audit trails',
        'GDPR Article 32 - Security of Processing'
      ],
      riskScore: isDeleted ? 75 : isCreated ? 55 : 40,
      resourceDetails: {
        itemType: isFolder ? 'Folder' : 'File',
        itemName: change.itemName,
        fullPath: `${change.path}/${change.itemName}`,
        parentPath: change.path,
        changeType: change.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        action: isCreated ? 'Created' : isDeleted ? 'Deleted' : 'Modified',
        timestamp: change.timestamp,
        detectionMethod: 'Agentless API-based Monitoring',
        monitoringType: 'Real-time File System Surveillance',
        environment: 'Windows Cloud Preview Environment',
        detectionSource: 'File System Events API',
        alertLevel: isDeleted ? 'High' : isCreated ? 'Medium' : 'Low',
        requiresReview: isDeleted || isCreated,
        changeId: change.id
      }
    });
  });
  
  // Agentless can't detect deep threats like suspicious processes, memory threats, rootkits, weak passwords, etc.
  const agentlessSkip = [
    'suspicious-process', 'memory-threat', 'rootkit-detected', 'weak-password', 
    'default-password', 'default-credentials', 'unauthorized-ssh-keys',
    'no-antivirus', 'excessive-privileges', 'unpatched-kernel', 'exposed-api-key'
  ];
  
  // VMs - Limited inspection via API
  environment.vms.forEach(vm => {
    vm.vulnerabilities.forEach(vuln => {
      if (!agentlessSkip.includes(vuln)) {
        const details = getVulnerabilityDetails(vuln, vm);
        findings.push({
          resourceId: vm.id,
          resourceName: vm.name,
          resourceType: 'VM',
          severity: details.severity,
          vulnerability: vuln,
          vulnerabilityTitle: details.title,
          description: details.description,
          testType: getTestType(vuln),
          detected: true,
          detectedBy: 'agentless',
          cvss: details.cvss,
          cve: details.cve,
          impact: details.impact,
          remediation: details.remediation,
          complianceImpact: details.complianceImpact,
          riskScore: details.riskScore,
          resourceDetails: {
            os: vm.os,
            publicIP: vm.publicIP,
            region: vm.region,
            instanceType: vm.instanceType,
            launchedAt: vm.launchedAt
          }
        });
      }
    });
  });
  
  // Databases - Can detect some issues via API
  environment.databases.forEach(db => {
    db.vulnerabilities.forEach(vuln => {
      if (!agentlessSkip.includes(vuln)) {
        const details = getVulnerabilityDetails(vuln, db);
        findings.push({
          resourceId: db.id,
          resourceName: db.name,
          resourceType: 'Database',
          severity: details.severity,
          vulnerability: vuln,
          vulnerabilityTitle: details.title,
          description: details.description,
          testType: getTestType(vuln),
          detected: true,
          detectedBy: 'agentless',
          cvss: details.cvss,
          cve: details.cve,
          impact: details.impact,
          remediation: details.remediation,
          complianceImpact: details.complianceImpact,
          riskScore: details.riskScore,
          resourceDetails: {
            type: db.type,
            version: db.version,
            encryption: db.encryption,
            connections: db.connections
          }
        });
      }
    });
  });
  
  // Storage - Good API coverage
  environment.storage.forEach(bucket => {
    bucket.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, bucket);
      findings.push({
        resourceId: bucket.id,
        resourceName: bucket.name,
        resourceType: 'Storage',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agentless',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          public: bucket.public,
          encryption: bucket.encryption,
          objects: bucket.objects,
          size: bucket.size
        }
      });
    });
  });
  
  // IAM - Good API coverage but misses some
  environment.iam.forEach(role => {
    role.vulnerabilities.forEach(vuln => {
      if (vuln !== 'exposed-api-key') { // Harder to detect without agent
        const details = getVulnerabilityDetails(vuln, role);
        findings.push({
          resourceId: role.id,
          resourceName: role.name,
          resourceType: 'IAM Role',
          severity: details.severity,
          vulnerability: vuln,
          vulnerabilityTitle: details.title,
          description: details.description,
          testType: getTestType(vuln),
          detected: true,
          detectedBy: 'agentless',
          cvss: details.cvss,
          cve: details.cve,
          impact: details.impact,
          remediation: details.remediation,
          complianceImpact: details.complianceImpact,
          riskScore: details.riskScore,
          resourceDetails: {
            permissions: role.permissions,
            users: role.users,
            lastUsed: role.lastUsed
          }
        });
      }
    });
  });
  
  // Network - Good API coverage
  environment.network.forEach(sg => {
    sg.vulnerabilities.forEach(vuln => {
      const details = getVulnerabilityDetails(vuln, sg);
      findings.push({
        resourceId: sg.id,
        resourceName: sg.name,
        resourceType: 'Security Group',
        severity: details.severity,
        vulnerability: vuln,
        vulnerabilityTitle: details.title,
        description: details.description,
        testType: getTestType(vuln),
        detected: true,
        detectedBy: 'agentless',
        cvss: details.cvss,
        cve: details.cve,
        impact: details.impact,
        remediation: details.remediation,
        complianceImpact: details.complianceImpact,
        riskScore: details.riskScore,
        resourceDetails: {
          rules: sg.rules,
          attachedResources: sg.attachedResources
        }
      });
    });
  });
  
  const scanTime = 6000 + Math.random() * 4000; // 6-10 seconds
  
  return {
    findings,
    stats: {
      totalResources: environment.vms.length + environment.databases.length + environment.storage.length + environment.iam.length + environment.network.length,
      vulnerabilitiesFound: findings.length,
      criticalIssues: findings.filter(f => f.severity === 'critical').length,
      highIssues: findings.filter(f => f.severity === 'high').length,
      mediumIssues: findings.filter(f => f.severity === 'medium').length,
      lowIssues: findings.filter(f => f.severity === 'low').length,
      scanTime: Math.round(scanTime),
      testsRun: securityTests.filter(t => t.agentless).length,
      detectionRate: 72,
      avgRiskScore: Math.round(findings.reduce((sum, f) => sum + f.riskScore, 0) / (findings.length || 1))
    }
  };
}

// Detailed vulnerability information database
function getVulnerabilityDetails(vuln, resource) {
  const vulnDatabase = {
    'open-ssh-port': {
      title: 'SSH Port Exposed to Internet',
      description: 'SSH port 22 is open to the internet (0.0.0.0/0)',
      severity: 'critical',
      cvss: 9.8,
      cve: ['CVE-2023-48795', 'CVE-2023-51385'],
      impact: 'Attackers can attempt brute force attacks, exploit SSH vulnerabilities, or gain unauthorized access to the system.',
      remediation: [
        'Restrict SSH access to specific IP addresses or VPN ranges',
        'Implement SSH key-based authentication only',
        'Change SSH default port from 22 to non-standard port',
        'Enable fail2ban or similar intrusion prevention',
        'Implement 2FA for SSH access'
      ],
      complianceImpact: ['CIS AWS Foundations 4.1', 'PCI-DSS 2.2.4', 'SOC2 CC6.6'],
      detectedBy: 'both',
      riskScore: 95
    },
    'weak-password': {
      title: 'Weak or Default Password Detected',
      description: 'Instance uses weak or easily guessable password that can be compromised',
      severity: 'critical',
      cvss: 9.1,
      cve: null,
      impact: 'Weak passwords can be easily cracked through brute force or dictionary attacks, leading to unauthorized system access and potential data breaches.',
      remediation: [
        'Enforce strong password policy (minimum 14 characters, mixed case, numbers, symbols)',
        'Implement password rotation every 90 days',
        'Use password manager for generating and storing secure passwords',
        'Enable multi-factor authentication (MFA)',
        'Monitor for failed login attempts'
      ],
      complianceImpact: ['NIST 800-53 IA-5', 'ISO 27001 A.9.4.3', 'GDPR Article 32', 'SOC2 CC6.1'],
      detectedBy: 'agent-only',
      riskScore: 92
    },
    'outdated-packages': {
      title: 'Outdated Packages with Known Vulnerabilities',
      description: 'System has 23 outdated packages with known CVEs',
      severity: 'high',
      cvss: 7.5,
      cve: ['CVE-2024-1234', 'CVE-2024-5678', 'CVE-2023-9012'],
      impact: 'Outdated packages contain known vulnerabilities that attackers can exploit to gain system access, escalate privileges, or cause denial of service.',
      remediation: [
        'Update all packages to latest stable versions: apt-get update && apt-get upgrade',
        'Enable automatic security updates',
        'Implement vulnerability scanning in CI/CD pipeline',
        'Subscribe to security mailing lists for critical updates',
        'Test updates in staging before production deployment'
      ],
      complianceImpact: ['CIS Benchmark 1.8', 'PCI-DSS 6.2', 'HIPAA 164.308(a)(5)(ii)(B)'],
      detectedBy: 'both',
      riskScore: 78
    },
    'missing-security-patches': {
      title: 'Missing Critical Security Patches',
      description: 'System is missing 15 critical security patches',
      severity: 'high',
      cvss: 8.1,
      cve: ['CVE-2024-2468', 'CVE-2024-1357'],
      impact: 'Missing security patches leave systems vulnerable to known exploits that can be used for privilege escalation or remote code execution.',
      remediation: [
        'Apply all available security patches immediately',
        'Schedule regular patch management cycles',
        'Use configuration management tools (Ansible, Puppet) for automated patching',
        'Implement patch testing process'
      ],
      complianceImpact: ['CIS Controls 3.4', 'NIST CSF PR.IP-12'],
      detectedBy: 'both',
      riskScore: 82
    },
    'insecure-ssl': {
      title: 'Insecure SSL/TLS Configuration',
      description: 'Server using outdated TLS 1.0/1.1 protocols and weak cipher suites',
      severity: 'high',
      cvss: 7.4,
      cve: ['CVE-2014-3566 (POODLE)', 'CVE-2016-2183 (SWEET32)'],
      impact: 'Weak SSL/TLS configurations allow man-in-the-middle attacks, data interception, and protocol downgrade attacks.',
      remediation: [
        'Disable TLS 1.0 and TLS 1.1, use only TLS 1.2 and TLS 1.3',
        'Configure strong cipher suites only',
        'Enable HTTP Strict Transport Security (HSTS)',
        'Implement certificate pinning',
        'Regular SSL/TLS configuration audits'
      ],
      complianceImpact: ['PCI-DSS 4.1', 'NIST SP 800-52', 'HIPAA 164.312(e)(1)'],
      detectedBy: 'both',
      riskScore: 75
    },
    'default-password': {
      title: 'Default Database Credentials in Use',
      description: 'Database is using factory default credentials',
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      impact: 'Default credentials are publicly known and documented, allowing immediate unauthorized access to database and potential data breach.',
      remediation: [
        'Change all default passwords immediately',
        'Use strong, randomly generated passwords',
        'Implement database access controls and roles',
        'Enable database audit logging',
        'Restrict database access to application servers only'
      ],
      complianceImpact: ['CIS Database Benchmark 2.1', 'PCI-DSS 2.1', 'SOC2 CC6.1', 'GDPR Article 32'],
      detectedBy: 'agent-only',
      riskScore: 98
    },
    'unpatched-kernel': {
      title: 'Kernel Vulnerabilities Detected',
      description: 'Operating system kernel has 7 unpatched critical vulnerabilities',
      severity: 'critical',
      cvss: 8.8,
      cve: ['CVE-2024-1086', 'CVE-2023-6931', 'CVE-2023-4147'],
      impact: 'Kernel vulnerabilities can lead to privilege escalation, container escape, denial of service, and complete system compromise.',
      remediation: [
        'Update kernel to latest patched version',
        'Apply kernel live patching (KernelCare, kpatch)',
        'Schedule maintenance window for kernel updates',
        'Enable kernel address space layout randomization (KASLR)',
        'Implement kernel security modules (SELinux, AppArmor)'
      ],
      complianceImpact: ['CIS Controls 3.4', 'ISO 27001 A.12.6.1', 'SOC2 CC7.1'],
      detectedBy: 'agent-only',
      riskScore: 88
    },
    'no-encryption': {
      title: 'Data Not Encrypted at Rest',
      description: 'Storage volumes and databases are not encrypted',
      severity: 'critical',
      cvss: 8.2,
      cve: null,
      impact: 'Unencrypted data at rest can be accessed if physical storage is compromised, backup tapes are stolen, or snapshots are exposed.',
      remediation: [
        'Enable encryption at rest for all storage volumes',
        'Use AWS KMS, Azure Key Vault, or similar key management',
        'Encrypt database storage and backups',
        'Implement encryption key rotation policies',
        'Use field-level encryption for sensitive data'
      ],
      complianceImpact: ['GDPR Article 32', 'HIPAA 164.312(a)(2)(iv)', 'PCI-DSS 3.4', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 85
    },
    'excessive-privileges': {
      title: 'Service Running with Excessive Privileges',
      description: 'Application running with root/administrator privileges unnecessarily',
      severity: 'high',
      cvss: 7.2,
      cve: null,
      impact: 'If application is compromised, attacker gains elevated privileges allowing system-wide access and lateral movement.',
      remediation: [
        'Run services with least privilege principle',
        'Create dedicated service accounts with minimal permissions',
        'Use sudo/runas for specific elevated operations only',
        'Implement role-based access control (RBAC)',
        'Regular privilege access reviews'
      ],
      complianceImpact: ['CIS Benchmark 5.1', 'NIST 800-53 AC-6', 'ISO 27001 A.9.2.3'],
      detectedBy: 'agent-only',
      riskScore: 72
    },
    'exposed-admin-panel': {
      title: 'Administrative Panel Publicly Accessible',
      description: 'Admin interface exposed on public internet without IP restrictions',
      severity: 'critical',
      cvss: 9.1,
      cve: null,
      impact: 'Public admin panels are prime targets for brute force attacks, credential stuffing, and exploitation of admin interface vulnerabilities.',
      remediation: [
        'Restrict admin panel access to VPN or specific IP addresses',
        'Implement Web Application Firewall (WAF)',
        'Use separate domain/subdomain for admin access',
        'Enable rate limiting and account lockout',
        'Require MFA for all administrative access',
        'Use HTTPS only with strong TLS configuration'
      ],
      complianceImpact: ['OWASP Top 10 A01:2021', 'PCI-DSS 6.5.10', 'SOC2 CC6.6'],
      detectedBy: 'both',
      riskScore: 91
    },
    'weak-firewall': {
      title: 'Weak Firewall Rules Configuration',
      description: 'Firewall rules allow unrestricted access to multiple ports',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Overly permissive firewall rules expand attack surface, allowing port scanning, service exploitation, and unauthorized access.',
      remediation: [
        'Implement default deny policy',
        'Allow only necessary ports and protocols',
        'Restrict source IP ranges to known locations',
        'Separate internal and external traffic',
        'Regular firewall rule audits and cleanup',
        'Use network segmentation'
      ],
      complianceImpact: ['CIS AWS 4.1-4.5', 'NIST 800-53 SC-7', 'PCI-DSS 1.2'],
      detectedBy: 'both',
      riskScore: 76
    },
    'unencrypted-volumes': {
      title: 'Storage Volumes Not Encrypted',
      description: 'EBS volumes attached to instance are unencrypted',
      severity: 'high',
      cvss: 7.8,
      cve: null,
      impact: 'Unencrypted volumes can be accessed through snapshots, volume copies, or if physical storage is compromised.',
      remediation: [
        'Enable default EBS encryption in account settings',
        'Encrypt existing volumes using snapshot method',
        'Use AWS KMS for key management',
        'Implement encryption for all new volumes',
        'Regular compliance scanning'
      ],
      complianceImpact: ['GDPR Article 32', 'HIPAA 164.312(a)(2)(iv)', 'PCI-DSS 3.4'],
      detectedBy: 'both',
      riskScore: 79
    },
    'suspicious-process': {
      title: 'Suspicious Process Detected',
      description: 'Unknown process "cryptominer.exe" consuming high CPU resources',
      severity: 'critical',
      cvss: 9.3,
      cve: null,
      impact: 'Suspicious processes may indicate malware, cryptocurrency miners, backdoors, or active breach requiring immediate investigation.',
      remediation: [
        'Immediately isolate affected instance from network',
        'Capture memory dump and disk image for forensics',
        'Terminate suspicious process and remove malicious files',
        'Scan with updated antivirus/antimalware tools',
        'Review access logs for initial compromise vector',
        'Rebuild instance from known good state',
        'Change all credentials and rotate keys'
      ],
      complianceImpact: ['NIST CSF DE.CM-4', 'ISO 27001 A.12.2.1', 'SOC2 CC7.2'],
      detectedBy: 'agent-only',
      riskScore: 94
    },
    'memory-threat': {
      title: 'In-Memory Threat Detected',
      description: 'Malicious code detected in process memory space',
      severity: 'critical',
      cvss: 9.5,
      cve: null,
      impact: 'In-memory threats can steal credentials, keylog user input, exfiltrate data, and maintain persistence while evading disk-based detection.',
      remediation: [
        'Initiate incident response procedure immediately',
        'Capture full memory dump for analysis',
        'Isolate system from network',
        'Run EDR/advanced threat detection tools',
        'Identify and block command & control (C2) communications',
        'Restore from known clean backup',
        'Conduct full security audit'
      ],
      complianceImpact: ['NIST CSF RS.AN-3', 'ISO 27035', 'SOC2 CC7.3'],
      detectedBy: 'agent-only',
      riskScore: 96
    },
    'rootkit-detected': {
      title: 'Rootkit Detection Alert',
      description: 'System rootkit detected - compromised kernel modules found',
      severity: 'critical',
      cvss: 9.9,
      cve: null,
      impact: 'Rootkits provide persistent backdoor access, hide malicious activity, can steal credentials, and maintain deep system-level control.',
      remediation: [
        'CRITICAL: System is compromised - isolate immediately',
        'Do not trust any data or logs from compromised system',
        'Capture forensic images before shutdown',
        'Rebuild system from scratch using verified OS media',
        'Analyze rootkit in isolated environment',
        'Review all access from this system to other resources',
        'Rotate all credentials and secrets',
        'Investigate initial compromise vector'
      ],
      complianceImpact: ['NIST CSF RS.AN-1', 'ISO 27035', 'GDPR Breach Notification'],
      detectedBy: 'agent-only',
      riskScore: 99
    },
    'unauthorized-ssh-keys': {
      title: 'Unauthorized SSH Keys Detected',
      description: 'Unknown SSH public keys found in authorized_keys file',
      severity: 'critical',
      cvss: 9.4,
      cve: null,
      impact: 'Unauthorized SSH keys provide backdoor access for attackers to maintain persistence and return even after password changes.',
      remediation: [
        'Immediately remove unknown SSH keys from authorized_keys',
        'Audit all SSH keys across infrastructure',
        'Implement SSH key management solution',
        'Enable SSH key rotation policies',
        'Review SSH access logs for unauthorized access',
        'Investigate how unauthorized keys were added',
        'Implement file integrity monitoring (FIM)'
      ],
      complianceImpact: ['CIS Controls 16.9', 'NIST 800-53 AC-17', 'SOC2 CC6.2'],
      detectedBy: 'agent-only',
      riskScore: 93
    },
    'eol-operating-system': {
      title: 'End-of-Life Operating System',
      description: 'Ubuntu 18.04 LTS reached end of standard support (April 2023)',
      severity: 'critical',
      cvss: 8.6,
      cve: null,
      impact: 'EOL systems no longer receive security updates, leaving all future vulnerabilities unpatched and creating compliance violations.',
      remediation: [
        'Plan immediate migration to supported OS version (Ubuntu 22.04 LTS or 24.04 LTS)',
        'Document all applications and dependencies',
        'Test applications on new OS in staging',
        'Schedule migration during maintenance window',
        'Consider extended support options if migration delayed',
        'Isolate EOL systems on separate network segment'
      ],
      complianceImpact: ['PCI-DSS 6.2', 'HIPAA 164.308(a)(5)(ii)(B)', 'SOC2 CC8.1'],
      detectedBy: 'both',
      riskScore: 87
    },
    'multiple-cves': {
      title: 'Multiple High-Severity CVEs Detected',
      description: 'System affected by 34 CVEs with CVSS scores above 7.0',
      severity: 'critical',
      cvss: 9.2,
      cve: ['CVE-2024-3094', 'CVE-2024-0567', 'CVE-2023-48795', 'and 31 more'],
      impact: 'Multiple vulnerabilities significantly increase attack surface and probability of successful exploitation.',
      remediation: [
        'Prioritize patching by CVSS score and exploitability',
        'Apply all available security updates',
        'Consider replacing with new hardened instance',
        'Implement vulnerability management program',
        'Schedule regular vulnerability scans'
      ],
      complianceImpact: ['NIST 800-53 RA-5', 'ISO 27001 A.12.6.1', 'PCI-DSS 6.2'],
      detectedBy: 'both',
      riskScore: 92
    },
    'no-antivirus': {
      title: 'No Antivirus or Endpoint Protection',
      description: 'System has no antivirus, EDR, or endpoint protection installed',
      severity: 'high',
      cvss: 7.1,
      cve: null,
      impact: 'Without endpoint protection, system cannot detect or prevent malware, ransomware, or other malicious software.',
      remediation: [
        'Install enterprise-grade antivirus/EDR solution',
        'Enable real-time scanning and protection',
        'Configure automatic signature updates',
        'Implement application whitelisting',
        'Enable behavioral detection features',
        'Integrate with SIEM for centralized monitoring'
      ],
      complianceImpact: ['CIS Controls 10.1', 'NIST CSF PR.DS-6', 'PCI-DSS 5.1'],
      detectedBy: 'agent-only',
      riskScore: 71
    },
    'exposed-services': {
      title: 'Multiple Services Exposed to Internet',
      description: 'Detected 12 services listening on public IP including internal tools',
      severity: 'high',
      cvss: 7.8,
      cve: null,
      impact: 'Exposed services increase attack surface and provide entry points for exploitation, especially internal tools not designed for public access.',
      remediation: [
        'Audit all listening services and close unnecessary ports',
        'Move internal tools behind VPN or bastion host',
        'Implement service-specific security controls',
        'Use reverse proxy with authentication',
        'Regular port scanning and service inventory',
        'Implement micro-segmentation'
      ],
      complianceImpact: ['CIS AWS 4.1', 'OWASP ASVS 14.4', 'NIST 800-53 CM-7'],
      detectedBy: 'both',
      riskScore: 79
    },
    'public-access': {
      title: 'Resource Publicly Accessible',
      description: 'Resource is accessible from the internet without authentication',
      severity: 'critical',
      cvss: 8.9,
      cve: null,
      impact: 'Public access to sensitive resources can lead to data breaches, unauthorized modifications, and compliance violations.',
      remediation: [
        'Remove public access immediately',
        'Implement authentication and authorization',
        'Use private endpoints or VPC connections',
        'Enable access logging and monitoring',
        'Regular access audits',
        'Implement data classification and access policies'
      ],
      complianceImpact: ['GDPR Article 32', 'HIPAA 164.312(a)(1)', 'PCI-DSS 7.1', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 89
    },
    'no-backup': {
      title: 'No Backup Configuration',
      description: 'Database has no automated backup or recovery plan configured',
      severity: 'high',
      cvss: 7.1,
      cve: null,
      impact: 'Without backups, data loss from ransomware, hardware failure, or human error can be catastrophic and permanent.',
      remediation: [
        'Enable automated daily backups',
        'Configure backup retention policy (30+ days)',
        'Test backup restoration procedures regularly',
        'Store backups in separate region/account',
        'Encrypt backups at rest and in transit',
        'Document disaster recovery procedures',
        'Implement 3-2-1 backup strategy'
      ],
      complianceImpact: ['ISO 27001 A.12.3.1', 'SOC2 CC3.1', 'NIST CSF PR.IP-4'],
      detectedBy: 'both',
      riskScore: 73
    },
    'sql-injection-risk': {
      title: 'SQL Injection Vulnerability Risk',
      description: 'Database access patterns indicate potential SQL injection vectors',
      severity: 'critical',
      cvss: 9.0,
      cve: ['CWE-89'],
      impact: 'SQL injection can lead to unauthorized data access, data manipulation, authentication bypass, and complete database compromise.',
      remediation: [
        'Use parameterized queries/prepared statements exclusively',
        'Implement input validation and sanitization',
        'Apply principle of least privilege for database accounts',
        'Enable database query logging and monitoring',
        'Deploy Web Application Firewall (WAF)',
        'Conduct code security review',
        'Implement static application security testing (SAST)'
      ],
      complianceImpact: ['OWASP Top 10 A03:2021', 'PCI-DSS 6.5.1', 'CWE Top 25'],
      detectedBy: 'both',
      riskScore: 90
    },
    'default-credentials': {
      title: 'Default Credentials Detected',
      description: 'System is using factory default or vendor-supplied credentials',
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      impact: 'Default credentials are publicly documented in vendor manuals and automated scanning tools, allowing immediate unauthorized access.',
      remediation: [
        'Change all default credentials immediately',
        'Implement strong password policy',
        'Use unique passwords for each system',
        'Enable multi-factor authentication',
        'Audit all systems for default credentials',
        'Implement privileged access management (PAM)'
      ],
      complianceImpact: ['CIS Controls 4.1', 'PCI-DSS 2.1', 'NIST 800-53 IA-5', 'SOC2 CC6.1'],
      detectedBy: 'agent-only',
      riskScore: 98
    },
    'outdated-version': {
      title: 'Outdated Software Version',
      description: 'Software is 2+ major versions behind current release with known vulnerabilities',
      severity: 'high',
      cvss: 7.8,
      cve: ['CVE-2023-1234', 'CVE-2022-5678'],
      impact: 'Outdated software contains known, often publicly exploited vulnerabilities that are trivial to exploit.',
      remediation: [
        'Plan upgrade to latest stable version',
        'Review release notes and breaking changes',
        'Test upgrade in non-production environment',
        'Schedule maintenance window for upgrade',
        'Implement version management policy',
        'Subscribe to vendor security notifications'
      ],
      complianceImpact: ['PCI-DSS 6.2', 'NIST 800-53 SI-2', 'ISO 27001 A.12.6.1'],
      detectedBy: 'both',
      riskScore: 80
    },
    'no-audit-logs': {
      title: 'Audit Logging Not Enabled',
      description: 'System has no audit logging configured for security events',
      severity: 'high',
      cvss: 6.5,
      cve: null,
      impact: 'Without audit logs, security incidents cannot be detected, investigated, or proven for compliance and forensics.',
      remediation: [
        'Enable comprehensive audit logging',
        'Log authentication, authorization, and data access events',
        'Configure log retention per compliance requirements',
        'Centralize logs to SIEM or log management system',
        'Implement log monitoring and alerting',
        'Protect log integrity with write-once storage',
        'Regular log review procedures'
      ],
      complianceImpact: ['GDPR Article 30', 'HIPAA 164.312(b)', 'PCI-DSS 10', 'SOC2 CC7.2'],
      detectedBy: 'both',
      riskScore: 68
    },
    'no-authentication': {
      title: 'Service Lacks Authentication',
      description: 'Service is running without any authentication mechanism',
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      impact: 'Services without authentication allow anyone to access, modify, or delete data without any access controls.',
      remediation: [
        'Implement strong authentication immediately',
        'Use industry-standard authentication protocols (OAuth, SAML)',
        'Require authentication for all access',
        'Implement role-based access control',
        'Enable multi-factor authentication',
        'Restrict network access while implementing'
      ],
      complianceImpact: ['NIST 800-53 IA-2', 'ISO 27001 A.9.2.1', 'PCI-DSS 8.1', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 97
    },
    'public-endpoint': {
      title: 'Database Endpoint Publicly Accessible',
      description: 'Database is accessible directly from the internet',
      severity: 'critical',
      cvss: 9.1,
      cve: null,
      impact: 'Public database endpoints are prime targets for automated attacks, brute force, and exploitation of database vulnerabilities.',
      remediation: [
        'Move database to private subnet immediately',
        'Use VPC/private endpoints only',
        'Remove public IP assignment',
        'Access database only through application servers or VPN',
        'Enable connection encryption (SSL/TLS)',
        'Implement database firewall rules',
        'Regular security group audits'
      ],
      complianceImpact: ['CIS AWS 4.2', 'PCI-DSS 1.3', 'HIPAA 164.312(e)(1)', 'GDPR Article 32'],
      detectedBy: 'both',
      riskScore: 91
    },
    'no-versioning': {
      title: 'Bucket Versioning Disabled',
      description: 'S3 bucket versioning is not enabled, risking data loss',
      severity: 'medium',
      cvss: 5.5,
      cve: null,
      impact: 'Without versioning, accidental deletions or overwrites are permanent, and ransomware attacks can destroy data irreversibly.',
      remediation: [
        'Enable S3 bucket versioning immediately',
        'Configure lifecycle policies for version management',
        'Enable MFA delete for critical buckets',
        'Implement cross-region replication for DR',
        'Regular restore testing',
        'Document data recovery procedures'
      ],
      complianceImpact: ['SOC2 CC3.1', 'ISO 27001 A.12.3.1', 'NIST CSF PR.IP-4'],
      detectedBy: 'both',
      riskScore: 55
    },
    'weak-acl': {
      title: 'Weak Access Control List',
      description: 'ACL grants overly broad permissions including AllUsers or AuthenticatedUsers',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Weak ACLs can expose sensitive data publicly, violate data privacy regulations, and enable unauthorized modifications.',
      remediation: [
        'Review and restrict ACL permissions',
        'Remove public access grants',
        'Use IAM policies instead of ACLs when possible',
        'Enable S3 Block Public Access',
        'Implement bucket policies with explicit deny',
        'Regular access policy audits',
        'Use AWS Access Analyzer'
      ],
      complianceImpact: ['GDPR Article 32', 'CCPA', 'HIPAA 164.312(a)(1)', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 76
    },
    'sensitive-data-exposed': {
      title: 'Sensitive Data Exposed Publicly',
      description: 'Bucket contains PII, credentials, or sensitive data accessible without authentication',
      severity: 'critical',
      cvss: 9.6,
      cve: null,
      impact: 'Exposed sensitive data leads to privacy violations, identity theft, financial fraud, regulatory fines, and reputational damage.',
      remediation: [
        'URGENT: Remove public access immediately',
        'Move sensitive data to private, encrypted storage',
        'Implement data classification policies',
        'Enable data loss prevention (DLP) controls',
        'Audit what data was exposed and for how long',
        'Notify affected parties per breach notification requirements',
        'Implement data discovery and classification tools',
        'Review and update data handling procedures'
      ],
      complianceImpact: ['GDPR Article 33/34 (Breach Notification)', 'CCPA', 'HIPAA 164.410', 'PCI-DSS 12.10'],
      detectedBy: 'both',
      riskScore: 96
    },
    'no-logging': {
      title: 'Access Logging Not Enabled',
      description: 'Bucket access logging is disabled, preventing audit trail',
      severity: 'medium',
      cvss: 4.3,
      cve: null,
      impact: 'Without access logs, security incidents and data breaches cannot be detected or investigated effectively.',
      remediation: [
        'Enable S3 server access logging',
        'Configure CloudTrail for data events',
        'Set appropriate log retention period',
        'Centralize logs in secure logging bucket',
        'Implement log analysis and alerting',
        'Regular log reviews'
      ],
      complianceImpact: ['GDPR Article 30', 'HIPAA 164.312(b)', 'PCI-DSS 10.2', 'SOC2 CC7.2'],
      detectedBy: 'both',
      riskScore: 45
    },
    'no-lifecycle-policy': {
      title: 'No Lifecycle Policy Configured',
      description: 'Bucket lacks lifecycle policy leading to unnecessary costs and compliance risks',
      severity: 'low',
      cvss: 3.1,
      cve: null,
      impact: 'Without lifecycle policies, old data accumulates indefinitely, increasing costs and creating data retention compliance issues.',
      remediation: [
        'Implement lifecycle policies for data management',
        'Transition old data to cheaper storage classes',
        'Automatically delete data per retention policy',
        'Align lifecycle with legal/compliance requirements',
        'Document data retention schedule'
      ],
      complianceImpact: ['GDPR Article 5 (Storage Limitation)', 'SOC2 CC3.2'],
      detectedBy: 'both',
      riskScore: 32
    },
    'hardcoded-secrets': {
      title: 'Hardcoded Secrets Detected',
      description: 'Configuration files contain hardcoded passwords, API keys, or credentials',
      severity: 'critical',
      cvss: 9.8,
      cve: ['CWE-798'],
      impact: 'Hardcoded secrets in configuration files or code are easily discovered and provide attackers with credentials to access systems and data.',
      remediation: [
        'IMMEDIATE: Rotate all exposed credentials',
        'Remove hardcoded secrets from code and configs',
        'Use secrets management service (AWS Secrets Manager, HashiCorp Vault)',
        'Implement environment variables for configuration',
        'Scan code repositories for secrets',
        'Implement pre-commit hooks to prevent secret commits',
        'Enable secrets detection in CI/CD pipeline'
      ],
      complianceImpact: ['OWASP Top 10 A07:2021', 'CWE Top 25', 'PCI-DSS 6.5.3', 'NIST 800-53 IA-5'],
      detectedBy: 'both',
      riskScore: 98
    },
    'no-retention-policy': {
      title: 'No Log Retention Policy',
      description: 'Logs are not retained per compliance requirements',
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      impact: 'Inadequate log retention prevents long-term security analysis and violates compliance requirements for audit trails.',
      remediation: [
        'Define log retention policy based on compliance requirements',
        'Configure automatic log retention (typically 90-365+ days)',
        'Implement log archival to long-term storage',
        'Ensure logs are immutable during retention period',
        'Document retention policy and procedures'
      ],
      complianceImpact: ['GDPR Article 30', 'HIPAA 164.316(b)(2)', 'PCI-DSS 10.7', 'SOC2 CC7.2'],
      detectedBy: 'both',
      riskScore: 53
    },
    'overly-permissive': {
      title: 'Overly Permissive IAM Policy',
      description: 'IAM role has wildcard permissions (*:*:*) allowing full account access',
      severity: 'critical',
      cvss: 9.9,
      cve: null,
      impact: 'Overly permissive roles violate least privilege and allow compromised accounts to access all resources, escalate privileges, and persist.',
      remediation: [
        'Apply principle of least privilege',
        'Remove wildcard permissions (*)',
        'Grant only specific required permissions',
        'Use managed policies for common patterns',
        'Implement permission boundaries',
        'Regular access reviews and cleanup',
        'Use AWS Access Analyzer to identify unused permissions'
      ],
      complianceImpact: ['CIS AWS 1.16', 'NIST 800-53 AC-6', 'ISO 27001 A.9.2.3', 'PCI-DSS 7.1', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 99
    },
    'no-mfa': {
      title: 'Multi-Factor Authentication Not Enabled',
      description: 'Account or role does not require MFA for authentication',
      severity: 'critical',
      cvss: 8.1,
      cve: null,
      impact: 'Without MFA, compromised passwords provide immediate access with no additional security layer.',
      remediation: [
        'Enable MFA for all user accounts',
        'Require MFA for privileged operations',
        'Use hardware MFA tokens for highest security',
        'Implement conditional access policies',
        'Enforce MFA in IAM policies',
        'Regular MFA compliance audits',
        'Disable accounts without MFA enabled'
      ],
      complianceImpact: ['CIS AWS 1.1-1.4', 'NIST 800-53 IA-2(1)', 'PCI-DSS 8.3', 'HIPAA 164.312(a)(2)(i)'],
      detectedBy: 'both',
      riskScore: 82
    },
    'unused-permissions': {
      title: 'Unused Permissions Detected',
      description: 'Role has 15 permissions that have never been used in 90+ days',
      severity: 'medium',
      cvss: 5.8,
      cve: null,
      impact: 'Unused permissions unnecessarily expand attack surface if role is compromised.',
      remediation: [
        'Review unused permissions with AWS Access Analyzer',
        'Remove unused permissions following least privilege',
        'Implement 90-day permission review cycle',
        'Document business justification for all permissions',
        'Use permission boundaries',
        'Regular access cleanup'
      ],
      complianceImpact: ['NIST 800-53 AC-6', 'ISO 27001 A.9.2.3', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 58
    },
    'excessive-permissions': {
      title: 'Excessive IAM Permissions',
      description: 'Role has broad permissions across multiple services beyond requirements',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Excessive permissions allow lateral movement and privilege escalation if role is compromised.',
      remediation: [
        'Audit current permission usage',
        'Reduce to minimum required permissions',
        'Separate roles by function/service',
        'Use resource-level restrictions',
        'Implement tag-based access control',
        'Regular permission reviews'
      ],
      complianceImpact: ['CIS AWS 1.16', 'NIST 800-53 AC-6', 'PCI-DSS 7.1.2', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 76
    },
    'no-session-duration': {
      title: 'No Session Duration Limit',
      description: 'IAM role has no maximum session duration configured',
      severity: 'medium',
      cvss: 5.4,
      cve: null,
      impact: 'Long-lived sessions increase window of opportunity for session hijacking and credential theft.',
      remediation: [
        'Set maximum session duration (recommended: 1-4 hours)',
        'Implement session timeout policies',
        'Require re-authentication for sensitive operations',
        'Enable session revocation capabilities',
        'Monitor active sessions'
      ],
      complianceImpact: ['NIST 800-53 AC-12', 'ISO 27001 A.9.4.3', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 54
    },
    'exposed-api-key': {
      title: 'API Key Exposed',
      description: 'API key found in application logs, code repository, or public location',
      severity: 'critical',
      cvss: 9.8,
      cve: ['CWE-798'],
      impact: 'Exposed API keys provide attackers with authenticated access to cloud resources and services.',
      remediation: [
        'IMMEDIATE: Rotate exposed API key',
        'Scan all code repositories and logs for keys',
        'Remove keys from logs and code',
        'Use secrets management service',
        'Implement API key rotation policy',
        'Enable secrets scanning in CI/CD',
        'Use IAM roles instead of long-lived keys when possible',
        'Monitor API key usage for anomalies'
      ],
      complianceImpact: ['OWASP Top 10 A07:2021', 'CWE-798', 'PCI-DSS 6.5.3', 'NIST 800-53 IA-5'],
      detectedBy: 'agent-only',
      riskScore: 98
    },
    'no-rotation': {
      title: 'Credential Rotation Not Configured',
      description: 'Credentials have not been rotated in 180+ days',
      severity: 'high',
      cvss: 7.2,
      cve: null,
      impact: 'Long-lived credentials increase risk of compromise and violate security best practices.',
      remediation: [
        'Rotate all credentials immediately',
        'Implement 90-day rotation policy',
        'Use automated credential rotation',
        'Enable rotation alerts and monitoring',
        'Document rotation procedures',
        'Prefer temporary credentials when possible'
      ],
      complianceImpact: ['CIS AWS 1.4', 'NIST 800-53 IA-5(1)', 'PCI-DSS 8.2.4', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 72
    },
    'permanent-credentials': {
      title: 'Permanent Credentials in Use',
      description: 'Service using long-lived IAM access keys instead of temporary credentials',
      severity: 'high',
      cvss: 7.1,
      cve: null,
      impact: 'Permanent credentials cannot be automatically rotated and provide persistent access if compromised.',
      remediation: [
        'Replace access keys with IAM roles for applications',
        'Use temporary security credentials (STS)',
        'Implement credential rotation if keys required',
        'Monitor access key age and usage',
        'Remove unused access keys',
        'Prefer instance profiles and service roles'
      ],
      complianceImpact: ['CIS AWS 1.4', 'NIST 800-53 IA-5', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 71
    },
    'privilege-escalation-risk': {
      title: 'Privilege Escalation Risk',
      description: 'IAM permissions allow potential privilege escalation vectors',
      severity: 'critical',
      cvss: 8.8,
      cve: null,
      impact: 'Privilege escalation allows attackers to gain higher-level access and potentially full account compromise.',
      remediation: [
        'Review and restrict IAM permissions',
        'Remove permission combinations that enable escalation',
        'Implement permission boundaries',
        'Use SCPs to prevent escalation',
        'Monitor for escalation attempts',
        'Regular privilege escalation risk assessments'
      ],
      complianceImpact: ['NIST 800-53 AC-6', 'CWE-269', 'ISO 27001 A.9.2.3'],
      detectedBy: 'both',
      riskScore: 88
    },
    'cross-account-access': {
      title: 'Unrestricted Cross-Account Access',
      description: 'Role allows cross-account access without external ID or conditions',
      severity: 'high',
      cvss: 7.7,
      cve: null,
      impact: 'Insecure cross-account access can lead to confused deputy attacks and unauthorized access from external accounts.',
      remediation: [
        'Require external ID for cross-account roles',
        'Implement trust policy conditions',
        'Restrict to specific external accounts',
        'Enable MFA for sensitive cross-account access',
        'Monitor cross-account activity',
        'Regular trust relationship audits',
        'Document all cross-account access'
      ],
      complianceImpact: ['CIS AWS 1.19', 'NIST 800-53 AC-3', 'SOC2 CC6.2'],
      detectedBy: 'both',
      riskScore: 78
    },
    'open-ssh': {
      title: 'SSH Unrestricted Access',
      description: 'Security group allows SSH (port 22) from anywhere (0.0.0.0/0)',
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      impact: 'Unrestricted SSH access enables brute force attacks, credential stuffing, and exploitation of SSH vulnerabilities.',
      remediation: [
        'Restrict SSH to specific IP ranges or VPN',
        'Use AWS Systems Manager Session Manager instead',
        'Implement bastion hosts for SSH access',
        'Enable SSH key-based authentication only',
        'Disable password authentication',
        'Implement fail2ban or similar protection',
        'Monitor SSH access logs'
      ],
      complianceImpact: ['CIS AWS 4.1', 'NIST 800-53 AC-17', 'PCI-DSS 2.2.4', 'SOC2 CC6.6'],
      detectedBy: 'both',
      riskScore: 98
    },
    'permissive-rules': {
      title: 'Overly Permissive Security Group Rules',
      description: 'Multiple ports open to 0.0.0.0/0 including non-standard ports',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Permissive rules allow port scanning, service enumeration, and attacks on all exposed services.',
      remediation: [
        'Apply default deny, explicit allow principle',
        'Restrict sources to known IP ranges',
        'Close unnecessary ports',
        'Use separate security groups per tier',
        'Implement network segmentation',
        'Regular security group audits',
        'Remove unused security groups'
      ],
      complianceImpact: ['CIS AWS 4.1-4.5', 'NIST 800-53 SC-7', 'PCI-DSS 1.2'],
      detectedBy: 'both',
      riskScore: 76
    },
    'unrestricted-egress': {
      title: 'Unrestricted Outbound Traffic',
      description: 'Security group allows all outbound traffic without restrictions',
      severity: 'medium',
      cvss: 5.3,
      cve: null,
      impact: 'Unrestricted egress allows malware to communicate with command & control servers and exfiltrate data.',
      remediation: [
        'Implement egress filtering',
        'Allow only required outbound connections',
        'Use VPC endpoints for AWS services',
        'Monitor egress traffic for anomalies',
        'Implement data loss prevention controls',
        'Use web proxies for internet access'
      ],
      complianceImpact: ['NIST 800-53 SC-7', 'ISO 27001 A.13.1.3', 'PCI-DSS 1.2.1'],
      detectedBy: 'both',
      riskScore: 53
    },
    'open-database-ports': {
      title: 'Database Ports Open to Internet',
      description: 'Security group allows database ports (3306, 5432, 27017) from 0.0.0.0/0',
      severity: 'critical',
      cvss: 9.8,
      cve: null,
      impact: 'Exposed database ports allow direct database attacks, brute force, and exploitation of database vulnerabilities.',
      remediation: [
        'URGENT: Remove public database access',
        'Restrict to application security group only',
        'Use VPC private subnets for databases',
        'Implement database proxy/bastion if external access needed',
        'Enable database firewall rules',
        'Monitor database access attempts',
        'Use VPC endpoints'
      ],
      complianceImpact: ['CIS AWS 4.2', 'PCI-DSS 1.3', 'HIPAA 164.312(e)(1)', 'SOC2 CC6.6'],
      detectedBy: 'both',
      riskScore: 98
    },
    'no-traffic-filtering': {
      title: 'No Network Traffic Filtering',
      description: 'Network allows traffic without inspection or filtering',
      severity: 'high',
      cvss: 7.2,
      cve: null,
      impact: 'Lack of traffic filtering allows malicious traffic, lateral movement, and data exfiltration.',
      remediation: [
        'Implement network-based intrusion detection/prevention',
        'Deploy Web Application Firewall (WAF)',
        'Use VPC flow logs for traffic analysis',
        'Implement network segmentation',
        'Deploy traffic inspection appliances',
        'Enable AWS Network Firewall'
      ],
      complianceImpact: ['NIST 800-53 SC-7', 'PCI-DSS 1.3', 'ISO 27001 A.13.1.3'],
      detectedBy: 'both',
      riskScore: 72
    },
    'exposed-internal-ports': {
      title: 'Internal Application Ports Exposed',
      description: 'Ports 3000, 8080 exposed publicly - typically used for development/internal apps',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Internal application ports often lack production security hardening and expose management interfaces or debugging tools.',
      remediation: [
        'Close internal application ports from internet',
        'Use load balancer with proper security',
        'Restrict to VPN or internal network',
        'Disable debugging features in production',
        'Implement proper authentication',
        'Regular port scanning audits'
      ],
      complianceImpact: ['OWASP ASVS 14.4', 'NIST 800-53 CM-7', 'CIS Controls 9.2'],
      detectedBy: 'both',
      riskScore: 75
    },
    'weak-authentication': {
      title: 'Weak Authentication Mechanism',
      description: 'System uses basic authentication without encryption or proper password complexity',
      severity: 'critical',
      cvss: 8.8,
      cve: null,
      impact: 'Weak authentication allows easy credential compromise through various attack methods.',
      remediation: [
        'Implement strong authentication (OAuth 2.0, SAML)',
        'Enforce password complexity requirements',
        'Enable MFA for all users',
        'Use encrypted authentication channels only',
        'Implement account lockout after failed attempts',
        'Regular authentication security reviews'
      ],
      complianceImpact: ['NIST 800-63B', 'ISO 27001 A.9.4.2', 'PCI-DSS 8.2', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 88
    },
    'no-ssl': {
      title: 'SSL/TLS Not Configured',
      description: 'Database connections not encrypted with SSL/TLS',
      severity: 'critical',
      cvss: 8.1,
      cve: null,
      impact: 'Unencrypted connections expose credentials and data to interception via man-in-the-middle attacks.',
      remediation: [
        'Enable SSL/TLS for all database connections',
        'Require encrypted connections only',
        'Use TLS 1.2 or higher',
        'Implement certificate validation',
        'Disable legacy protocols',
        'Regular encryption audit'
      ],
      complianceImpact: ['PCI-DSS 4.1', 'HIPAA 164.312(e)(1)', 'GDPR Article 32', 'SOC2 CC6.7'],
      detectedBy: 'both',
      riskScore: 82
    },
    'exposed-port': {
      title: 'Sensitive Port Exposed',
      description: 'Service port exposed to internet that should be internal only',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Exposed sensitive ports allow attackers to target services directly, bypassing application-level security controls.',
      remediation: [
        'Move service to private subnet',
        'Use application load balancer as frontend',
        'Restrict access to VPN or bastion host',
        'Implement proper authentication and authorization',
        'Enable service-specific security features',
        'Monitor access to sensitive ports'
      ],
      complianceImpact: ['CIS Benchmark 3.4', 'NIST 800-53 SC-7', 'PCI-DSS 2.2.4'],
      detectedBy: 'both',
      riskScore: 76
    },
    'privileged-accounts': {
      title: 'Excessive Privileged Accounts',
      description: 'Multiple accounts have privileged access beyond requirements',
      severity: 'high',
      cvss: 7.2,
      cve: null,
      impact: 'Excessive privileged accounts increase attack surface and risk of insider threats.',
      remediation: [
        'Review and reduce privileged access',
        'Implement just-in-time (JIT) privileged access',
        'Use separate accounts for privileged operations',
        'Enable privileged access management (PAM)',
        'Monitor all privileged account activity',
        'Regular access reviews and recertification',
        'Implement approval workflows for privilege grants'
      ],
      complianceImpact: ['NIST 800-53 AC-6', 'ISO 27001 A.9.2.3', 'PCI-DSS 7.1', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 73
    },
    'overpermissive-policy': {
      title: 'Overly Permissive Resource Policy',
      description: 'Resource policy grants broad access to multiple principals',
      severity: 'high',
      cvss: 7.5,
      cve: null,
      impact: 'Overly permissive policies violate least privilege and enable unauthorized access.',
      remediation: [
        'Restrict resource policy to specific principals',
        'Use condition keys to limit access',
        'Review and remove unnecessary permissions',
        'Implement resource-based policies defensively',
        'Regular policy audits',
        'Use AWS Access Analyzer'
      ],
      complianceImpact: ['NIST 800-53 AC-6', 'CIS AWS Foundations', 'SOC2 CC6.1'],
      detectedBy: 'both',
      riskScore: 76
    }
  };
  
  return vulnDatabase[vuln] || {
    title: vuln.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
    description: 'Security vulnerability detected',
    severity: 'medium',
    cvss: 5.0,
    cve: null,
    impact: 'This vulnerability may pose a security risk to your infrastructure.',
    remediation: ['Review and address this security finding', 'Consult security documentation'],
    complianceImpact: [],
    detectedBy: 'both',
    riskScore: 50
  };
}

function getVulnerabilityDescription(vuln) {
  const details = getVulnerabilityDetails(vuln);
  return details.description;
}

function getTestType(vuln) {
  if (['open-ssh-port', 'open-ssh', 'open-database-ports', 'public-endpoint'].includes(vuln)) return 'port-scan';
  if (['weak-password', 'default-password', 'default-credentials', 'no-authentication'].includes(vuln)) return 'config-scan';
  if (['outdated-packages', 'unpatched-kernel', 'outdated-version'].includes(vuln)) return 'vuln-check';
  if (['no-encryption'].includes(vuln)) return 'encryption';
  if (['overly-permissive', 'no-mfa', 'excessive-permissions', 'exposed-api-key', 'no-rotation'].includes(vuln)) return 'iam-audit';
  if (['weak-firewall', 'permissive-rules'].includes(vuln)) return 'network-security';
  if (['suspicious-process', 'memory-threat'].includes(vuln)) return 'threat-detection';
  if (['public-access', 'sensitive-data-exposed'].includes(vuln)) return 'gdpr';
  return 'config-scan';
}

export async function GET(request) {
  const { pathname } = new URL(request.url);
  
  if (pathname === '/api/environment') {
    if (!globalEnvironment) {
      globalEnvironment = generateCloudEnvironment();
    }
    return NextResponse.json({ environment: globalEnvironment, tests: securityTests });
  }
  
  return NextResponse.json({ error: 'Not found' }, { status: 404 });
}

export async function POST(request) {
  const { pathname } = new URL(request.url);
  const body = await request.json();
  
  // Initialize environment if not exists
  if (!globalEnvironment) {
    globalEnvironment = generateCloudEnvironment();
  }
  
  if (pathname === '/api/add-resource') {
    const { resourceType, ...resourceData } = body;
    
    // Add random vulnerabilities
    const commonVulns = ['no-encryption', 'weak-firewall', 'outdated-packages', 'missing-security-patches'];
    resourceData.vulnerabilities = commonVulns.slice(0, Math.floor(Math.random() * 3) + 1);
    
    if (resourceType === 'vm') {
      resourceData.status = 'running';
      resourceData.publicIP = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      resourceData.launchedAt = new Date().toISOString().split('T')[0];
      globalEnvironment.vms.push(resourceData);
    } else if (resourceType === 'database') {
      resourceData.encryption = false;
      resourceData.connections = Math.floor(Math.random() * 500) + 10;
      globalEnvironment.databases.push(resourceData);
    } else if (resourceType === 'storage') {
      resourceData.type = 'S3 Bucket';
      resourceData.objects = Math.floor(Math.random() * 10000) + 100;
      globalEnvironment.storage.push(resourceData);
    }
    
    return NextResponse.json({ environment: globalEnvironment });
  }
  
  if (pathname === '/api/scan/agent-based') {
    const { selectedResources, fileSystemChanges = [] } = body;
    const filteredEnvironment = filterEnvironmentBySelection(globalEnvironment, selectedResources);
    const results = runAgentBasedScan(filteredEnvironment, fileSystemChanges);
    return NextResponse.json(results);
  }
  
  if (pathname === '/api/scan/agentless') {
    const { selectedResources } = body;
    const filteredEnvironment = filterEnvironmentBySelection(globalEnvironment, selectedResources);
    const results = runAgentlessScan(filteredEnvironment);
    return NextResponse.json(results);
  }
  
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

// Filter environment based on selected resources
function filterEnvironmentBySelection(environment, selectedResources) {
  if (!selectedResources || selectedResources.length === 0) {
    return environment;
  }
  
  return {
    vms: environment.vms.filter(vm => selectedResources.includes(vm.id)),
    databases: environment.databases.filter(db => selectedResources.includes(db.id)),
    storage: environment.storage.filter(s => selectedResources.includes(s.id)),
    iam: environment.iam.filter(i => selectedResources.includes(i.id)),
    network: environment.network.filter(n => selectedResources.includes(n.id))
  };
}
