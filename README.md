# Cloud Security Comparison Platform

A comprehensive Next.js web application that demonstrates and compares **Agent-Based** vs **Agentless** cloud security tools through realistic security scanning simulations.

![Cloud Security Comparison](https://img.shields.io/badge/Next.js-14.2.3-black?style=for-the-badge&logo=next.js)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)

## 🎯 Overview

This application simulates a realistic multi-service cloud environment (AWS/Azure/GCP-like) with intentional security vulnerabilities and demonstrates how two different security scanning approaches detect and report these issues:

- **Agent-Based Security Tool**: Deep inspection with installed agents on each resource
- **Agentless Security Tool**: API-based scanning without agent installation

## ✨ Features

### 🖥️ **NEW: Interactive Windows Cloud Preview Environment**
- **Real-time File System Monitoring**: Create files and folders in a simulated Windows environment
- **Instant Security Detection**: All file/folder changes are automatically tracked and analyzed
- **Agentless Integration**: Created items appear in real-time in the Agentless Security Findings
- **Detailed Security Analysis**: Click any detected file/folder to view:
  - CVSS scores and risk assessments
  - Compliance mapping (SOC2, ISO 27001, NIST, PCI-DSS, GDPR)
  - 8 actionable remediation steps
  - Full change history with timestamps
- **Interactive Desktop**: Complete Windows-like environment with:
  - File Explorer for navigating directories
  - Desktop icons (This PC, Recycle Bin, Documents, Downloads)
  - Right-click context menus for creating files/folders
  - Notepad for viewing and editing text files
  - Taskbar with Start menu and running applications

### 🔒 Comprehensive Security Scanning
- **10 Security Test Types**:
  - Configuration Scans
  - Vulnerability Checks (CVE detection)
  - Open Port Detection
  - IAM Permission Audits
  - Encryption Checks
  - Network Security Analysis
  - CIS Benchmark Compliance
  - SOC2 Compliance
  - GDPR Compliance
  - Threat Detection (In-memory threats, rootkits, suspicious processes)
  - **File System Change Detection** (NEW)

### 🌐 Simulated Cloud Environment
- **5 Virtual Machines** (Ubuntu, CentOS, Debian) with realistic configurations
- **4 Databases** (PostgreSQL, MongoDB, Redis, MySQL) with connection metrics
- **4 Storage Buckets** (S3-style) with size and object counts
- **4 IAM Roles** with permission sets and usage tracking
- **3 Security Groups** with firewall rules and attached resources
- **Windows Cloud Preview** (NEW): Interactive Windows environment for file system testing

### 📊 Interactive Dashboards
- **Side-by-Side Comparison**: Real-time scanning progress and results
- **Similarities & Differences Analysis**: Visual breakdown of detection overlap
- **Performance Metrics**: Speed, detection rate, and risk scores
- **Detailed Vulnerability Reports**: Click any vulnerability for in-depth information

### 🔍 Realistic Vulnerability Database
Each vulnerability includes:
- **CVSS Scores** (3.1 - 9.9)
- **CVE References** (real CVE identifiers)
- **Risk Scores** (0-100)
- **Impact Analysis** (business and technical impact)
- **Remediation Steps** (numbered, actionable guidance)
- **Compliance Mapping** (GDPR, HIPAA, PCI-DSS, SOC2, CIS, NIST, ISO 27001)

### 📈 Key Differentiators

| Metric | Agent-Based | Agentless |
|--------|-------------|-----------|
| **Vulnerabilities Found** | 66 | 54 |
| **Detection Rate** | 95% | 72% |
| **Scan Speed** | 18-26 seconds | 6-10 seconds |
| **Tests Run** | 10/10 | 7/10 |
| **Average Risk Score** | 81/100 | 79/100 |
| **Deployment** | Agent installation required | API permissions only |

### 🚫 Agentless Blind Spots
Vulnerabilities that agentless tools **cannot detect**:
- In-memory threats
- Weak/default passwords
- Suspicious processes
- Rootkit detection
- Exposed API keys in files
- Kernel vulnerabilities
- Missing antivirus/EDR
- Excessive service privileges

## 🛠️ Technology Stack

- **Frontend**: Next.js 14.2.3, React 18
- **UI Components**: shadcn/ui, Tailwind CSS
- **Backend**: Next.js API Routes
- **Database**: MongoDB (for potential extensions)
- **Icons**: Lucide React
- **Styling**: Tailwind CSS with custom design system

## 🖥️ Windows Cloud Preview - Detailed Guide

The Windows Cloud Preview is an interactive environment that simulates a Windows operating system for security testing purposes.

### Features

#### 🎯 Real-time File System Monitoring
Every file or folder you create is automatically:
- **Tracked**: Change type, name, path, and timestamp recorded
- **Analyzed**: Security impact assessment performed
- **Reported**: Appears in Agentless Security Findings
- **Detailed**: Click for comprehensive security analysis

#### 🗂️ File System Operations
- **Create Files**: Right-click → New → Text Document
- **Create Folders**: Right-click → New → Folder
- **Navigate**: Use File Explorer to browse directories
- **Edit Files**: Double-click text files to open in Notepad
- **Desktop Icons**: Quick access to common locations

#### 📊 Security Detection Levels
| Action | Severity | CVSS Score | Risk Score |
|--------|----------|------------|------------|
| File Created | Medium | 5.5 | 55 |
| Folder Created | Medium | 5.5 | 55 |
| File Deleted | High | 7.5 | 75 |
| Folder Deleted | High | 7.5 | 75 |
| File Modified | Low | 4.0 | 40 |

#### 🔐 Security Analysis Includes
- **CVSS Scoring**: Industry-standard vulnerability scoring
- **Risk Assessment**: Automated risk calculation
- **Compliance Mapping**: 
  - SOC2 (CC6.1, CC7.2)
  - ISO 27001 (A.12.4.1, A.18.1.3)
  - NIST 800-53 (AU-2, AU-6, CM-3)
  - PCI-DSS (10.2)
  - GDPR (Article 32)
- **Remediation Steps**: 8 actionable security recommendations
- **Impact Analysis**: Business and technical impact assessment

### How It Works

1. **User Action**: Create/delete/modify file or folder in Windows environment
2. **Detection**: Change is captured with full metadata
3. **Transmission**: Change data sent to scanning system
4. **Analysis**: Agentless scanner evaluates security implications
5. **Reporting**: Finding appears in Agentless Security Findings
6. **Detail View**: Click to see comprehensive analysis

### Integration with Agentless Scanner

The Windows Cloud Preview integrates seamlessly with the Agentless Security Tool:
- Changes are tracked in real-time
- No agent installation required (API-based monitoring)
- Demonstrates agentless detection capabilities
- Shows limitations compared to agent-based scanning

## 📦 Installation

### Prerequisites
- Node.js 18+ or Yarn
- MongoDB (optional, for extensions)

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd cloud-security-comparison
```

2. **Install dependencies**
```bash
yarn install
```

3. **Environment Variables**
Create a `.env` file in the root directory:
```env
MONGO_URL=mongodb://localhost:27017/cloud-security
NEXT_PUBLIC_BASE_URL=http://localhost:3000
```

4. **Run the development server**
```bash
yarn dev
```

5. **Open in browser**
Navigate to [http://localhost:3000](http://localhost:3000)

## 🚀 Usage

### Running Security Scans

1. **Click "Run Both Scans"** to execute both agent-based and agentless scans simultaneously
2. **Or run individually** by clicking the respective "Start Scan" buttons
3. **View real-time progress** with animated progress bars
4. **Analyze results** in the side-by-side comparison view

### 🆕 Using the Windows Cloud Preview Environment

1. **Open Cloud Preview**: Click the "Cloud Preview" button in the top navigation bar
2. **Interact with the Environment**:
   - **Desktop**: Right-click to create new folders or files
   - **File Explorer**: Double-click "This PC", "Documents", or any folder icon
   - **Create Items**: Right-click in any folder → New → Folder or Text Document
   - **Navigate**: Use File Explorer to browse through directories (C:\, Users, Documents, etc.)
3. **Real-time Security Monitoring**:
   - All file/folder creations are automatically tracked
   - Changes appear instantly in the file system change log
4. **Run Agentless Scan**: Click "Start Scan" on the Agentless Security Tool
5. **View Detected Changes**:
   - Created files/folders appear in "Agentless Detailed Security Findings"
   - Each item shows severity level, timestamp, and full path
6. **View Detailed Analysis**: Click any file/folder entry to see:
   - Complete security impact assessment
   - CVSS scores and risk ratings
   - Compliance framework mapping
   - Remediation recommendations

### Viewing Vulnerability Details

1. **Scroll to "Detailed Security Findings"** section
2. **Click on any vulnerability** (including file system changes) to open the detailed modal
3. **Review**:
   - Vulnerability overview and severity
   - Affected resource details
   - CVE references (where applicable)
   - Impact analysis
   - Step-by-step remediation
   - Compliance requirements
   - For file system changes: Full path, change type, timestamp, and detection method

### Understanding the Comparison

- **Both Detected**: Vulnerabilities found by both tools (common ground)
- **Agent-Based Only**: Critical issues agentless tools miss
- **Missed by Agentless**: Security blind spots requiring agent deployment
- **File System Changes**: Real-time monitoring of files/folders created in Cloud Preview (Agentless only)

## 📡 API Endpoints

### `GET /api/environment`
Returns the simulated cloud environment with all resources and their vulnerabilities.

**Response:**
```json
{
  "environment": {
    "vms": [...],
    "databases": [...],
    "storage": [...],
    "iam": [...],
    "network": [...]
  },
  "tests": [...]
}
```

### `POST /api/scan/agent-based`
Executes agent-based security scan and returns findings.

**Request Body:**
```json
{
  "selectedResources": ["vm-001", "db-001", ...]
}
```

**Response:**
```json
{
  "findings": [...],
  "stats": {
    "totalResources": 20,
    "vulnerabilitiesFound": 66,
    "criticalIssues": 36,
    "highIssues": 23,
    "mediumIssues": 6,
    "lowIssues": 1,
    "scanTime": 21828,
    "testsRun": 10,
    "detectionRate": 95,
    "avgRiskScore": 81
  },
  "zeroTrustScore": {...},
  "anomalyDetections": {...},
  "runtimeThreats": {...}
}
```

### `POST /api/scan/agentless`
Executes agentless security scan and returns findings, including file system changes.

**Request Body:**
```json
{
  "selectedResources": ["vm-001", "db-001", ...],
  "fileSystemChanges": [
    {
      "type": "file_created",
      "path": "C:\\Users\\Admin\\Documents",
      "itemName": "report.txt",
      "timestamp": "11/11/2025, 6:45:00 PM",
      "id": 1731349500123
    }
  ]
}
```

**Response:**
```json
{
  "findings": [
    {
      "resourceId": "vm-windows-cloud-preview",
      "resourceName": "Windows Cloud Environment",
      "resourceType": "File System",
      "severity": "medium",
      "vulnerabilityTitle": "File Created: report.txt",
      "description": "Agentless scan detected file creation...",
      "cvss": 5.5,
      "riskScore": 55,
      "resourceDetails": {
        "itemType": "File",
        "itemName": "report.txt",
        "fullPath": "C:\\Users\\Admin\\Documents/report.txt",
        "changeType": "File Created",
        "timestamp": "11/11/2025, 6:45:00 PM",
        "detectionMethod": "Agentless API-based Monitoring"
      }
    }
  ],
  "stats": {
    "totalResources": 20,
    "vulnerabilitiesFound": 54,
    "criticalIssues": 26,
    "highIssues": 21,
    "mediumIssues": 6,
    "lowIssues": 1,
    "scanTime": 8227,
    "testsRun": 7,
    "detectionRate": 72,
    "avgRiskScore": 79
  }
}
```

### `POST /api/agent-scan`
Executes CLI-based agent scanning on uploaded files.

**Request Body:** FormData with file and command

**Response:**
```json
{
  "command": "test_insecure",
  "fileType": "Python",
  "linesAnalyzed": 42,
  "scanTime": 1250,
  "vulnerabilities": [...],
  "summary": {
    "totalIssues": 5,
    "critical": 2,
    "high": 2,
    "medium": 1,
    "low": 0,
    "securityScore": 45,
    "status": "Multiple critical security issues detected"
  },
  "recommendations": [...]
}
```

### `POST /api/scan-files`
Scans multiple files for security vulnerabilities.

**Request Body:**
```json
{
  "files": [
    {
      "name": "config.json",
      "content": "{...}",
      "type": "application/json",
      "size": 245
    }
  ]
}
```

**Response:**
```json
{
  "findings": [...],
  "stats": {
    "totalIssues": 12,
    "critical": 3,
    "high": 4,
    "medium": 3,
    "low": 2
  }
}
```

## 🏗️ Project Structure

```
/app
├── app/
│   ├── api/
│   │   └── [[...path]]/
│   │       └── route.js          # Backend API routes
│   ├── page.js                   # Main application page
│   ├── layout.js                 # Root layout
│   └── globals.css              # Global styles
├── components/
│   └── ui/                       # shadcn/ui components
├── lib/
│   └── utils/                    # Utility functions
├── public/                       # Static assets
├── .env                          # Environment variables
├── package.json                  # Dependencies
├── tailwind.config.js           # Tailwind configuration
└── README.md                     # This file
```

## 🎨 Key Components

### Frontend (`/app/app/page.js`)
- **CloudSecurityComparison**: Main React component
- **State Management**: Handles scan results, progress, modal state, and file system changes
- **UI Sections**:
  - Cloud Environment Overview
  - Windows Cloud Preview Environment (NEW)
  - Side-by-Side Scan Cards
  - Similarities & Differences Analysis
  - Performance Comparison Charts
  - Detailed Findings Tabs
  - Vulnerability Detail Modal
  - File System Change Tracking (NEW)

### Windows Environment (`/app/components/WindowsEnvironment.js`)
- **WindowsEnvironment**: Complete Windows simulation component
- **File System Management**: Real-time file/folder creation and tracking
- **Desktop Interface**: Icons, taskbar, start menu
- **Applications**:
  - **FileExplorer**: Navigate directories and manage files
  - **Notepad**: View and edit text files
  - **BrowserWindow**: Web browsing simulation
- **Context Menus**: Right-click functionality for file operations
- **Change Detection**: Automatically notifies parent component of file system modifications

### Security Scanners
- **AgentScanner** (`/app/components/AgentScanner.js`): 
  - CLI-based file scanning with multiple commands
  - Upload and scan code files for vulnerabilities
  - Detailed security reports with remediation steps
- **FileScanner** (`/app/components/FileScanner.js`):
  - Drag-and-drop file upload
  - Multi-file security analysis
  - Code vulnerability detection

### Backend (`/app/app/api/[[...path]]/route.js`)
- **generateCloudEnvironment()**: Creates realistic cloud infrastructure
- **getVulnerabilityDetails()**: Comprehensive vulnerability database
- **runAgentBasedScan()**: Simulates deep agent-based scanning
- **runAgentlessScan()**: Simulates API-based agentless scanning with file system change detection (NEW)
- **API Routes**: RESTful endpoints for frontend consumption

### Additional API Routes
- `/api/agent-scan`: CLI-based security scanning
- `/api/scan-files`: Multi-file vulnerability analysis

## 🔐 Vulnerability Categories

### Critical Vulnerabilities
- SSH exposed to internet (CVSS 9.8)
- Rootkit detection (CVSS 9.9)
- Hardcoded secrets (CVSS 9.8)
- Default credentials (CVSS 9.8)
- In-memory threats (CVSS 9.5)
- Sensitive data exposed (CVSS 9.6)

### High Vulnerabilities
- Unpatched kernels (CVSS 8.8)
- End-of-life OS (CVSS 8.6)
- Multiple CVEs (CVSS 9.2)
- No encryption at rest (CVSS 8.2)
- Weak SSL/TLS (CVSS 7.4)

### Medium & Low Vulnerabilities
- No bucket versioning (CVSS 5.5)
- Missing audit logs (CVSS 6.5)
- No lifecycle policies (CVSS 3.1)

## 📊 Compliance Frameworks

The application maps vulnerabilities to:
- **GDPR** (Article 30, 32, 33, 34)
- **HIPAA** (164.308, 164.312, 164.316, 164.410)
- **PCI-DSS** (1.2, 1.3, 2.1, 2.2, 3.4, 4.1, 6.2, 6.5, 7.1, 8.1, 8.2, 8.3, 10, 12.10)
- **SOC2** (CC3.1, CC6.1, CC6.2, CC6.6, CC6.7, CC7.1, CC7.2, CC7.3, CC8.1)
- **CIS Controls** (1.8, 3.4, 4.1, 5.1, 9.2, 10.1, 16.9)
- **NIST 800-53** (AC-3, AC-6, AC-12, AC-17, CM-7, IA-2, IA-5, RA-5, SC-7, SI-2)
- **ISO 27001** (A.9.2.3, A.9.4.2, A.9.4.3, A.12.2.1, A.12.3.1, A.12.6.1, A.13.1.3)
- **OWASP Top 10** (A01:2021, A03:2021, A07:2021)
- **CWE Top 25** (CWE-89, CWE-269, CWE-798)

## 🎯 Use Cases

### Educational
- Learn about cloud security scanning methodologies
- Understand the differences between agent-based and agentless approaches
- Study common cloud misconfigurations and vulnerabilities

### Professional
- Demonstrate security tool capabilities to stakeholders
- Compare security scanning solutions
- Training and awareness for security teams
- Sales demonstrations for security vendors

### Research
- Analyze detection coverage differences
- Study security tool performance metrics
- Evaluate compliance mapping accuracy

## 🚦 Performance Considerations

- **Scan Simulation Time**:
  - Agent-Based: 18-26 seconds (realistic deep inspection)
  - Agentless: 6-10 seconds (faster API-based scanning)
  
- **Progressive UI Updates**: Real-time progress bars during scans
- **Lazy Loading**: Modal content loads on-demand
- **Optimized Rendering**: Efficient React component updates

## ✅ Recently Added Features

- [x] **Windows Cloud Preview Environment**: Interactive Windows simulation for file system testing
- [x] **Real-time File System Monitoring**: Automatic tracking of file/folder creation, modification, and deletion
- [x] **Agentless File System Detection**: Files/folders appear in security findings with detailed analysis
- [x] **Enhanced Compliance Mapping**: SOC2, ISO 27001, NIST, PCI-DSS, GDPR for all detections
- [x] **Interactive Desktop Environment**: Full Windows-like interface with File Explorer and applications
- [x] **Agent Scanner**: CLI-based file security scanning with multiple command options
- [x] **File Scanner**: Drag-and-drop vulnerability scanning for code files

## 🔮 Future Enhancements

- [ ] Real-time cloud provider integration (AWS, Azure, GCP)
- [ ] Export scan results to PDF/CSV (JSON export currently available)
- [ ] Historical scan comparison
- [ ] Custom vulnerability rule engine
- [ ] Multi-cloud environment support
- [ ] Advanced filtering and search
- [ ] Risk score trending over time
- [ ] Remediation workflow tracking
- [ ] Integration with ticketing systems (Jira, ServiceNow)
- [ ] Automated remediation scripts
- [ ] Linux/MacOS environment simulations
- [ ] Docker container security scanning
- [ ] Kubernetes cluster security analysis

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- **Development Team** - Initial work and enhancements

## 🙏 Acknowledgments

- **shadcn/ui** for the beautiful component library
- **Tailwind CSS** for the utility-first CSS framework
- **Next.js** for the React framework
- **Lucide** for the icon set
- Security community for vulnerability research and CVE data

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact the development team

## 🎓 Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---

**Built with ❤️ for cloud security professionals**
