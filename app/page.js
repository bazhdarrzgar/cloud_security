'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Server, Database, HardDrive, Shield, Users, Network, AlertTriangle, CheckCircle, XCircle, Clock, Zap, Settings, Info, Eye, X, Lock, Activity, PlayCircle, Download, Monitor, Terminal } from 'lucide-react';
import WindowsEnvironment from '@/components/WindowsEnvironment';
import AgentScanner from '@/components/AgentScanner';

export default function CloudSecurityComparison() {
  const [environment, setEnvironment] = useState(null);
  const [tests, setTests] = useState([]);
  const [agentBasedResults, setAgentBasedResults] = useState(null);
  const [agentlessResults, setAgentlessResults] = useState(null);
  const [agentBasedScanning, setAgentBasedScanning] = useState(false);
  const [agentlessScanning, setAgentlessScanning] = useState(false);
  const [agentBasedProgress, setAgentBasedProgress] = useState(0);
  const [agentlessProgress, setAgentlessProgress] = useState(0);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [zeroTrustScore, setZeroTrustScore] = useState(null);
  const [anomalyDetections, setAnomalyDetections] = useState(null);
  const [runtimeThreats, setRuntimeThreats] = useState(null);
  const [showAddResourceModal, setShowAddResourceModal] = useState(false);
  const [resourceType, setResourceType] = useState('vm');
  const [selectedResources, setSelectedResources] = useState([]);
  const [showResourceSelector, setShowResourceSelector] = useState(false);
  const [showZeroTrustDetail, setShowZeroTrustDetail] = useState(false);
  const [showAnomalyDetail, setShowAnomalyDetail] = useState(false);
  const [showRuntimeDetail, setShowRuntimeDetail] = useState(false);
  const [showDashboard, setShowDashboard] = useState(false);
  const [showWindowsEnv, setShowWindowsEnv] = useState(false);
  const [fileSystemChanges, setFileSystemChanges] = useState([]);
  const [lastFileSystemState, setLastFileSystemState] = useState(null);
  const [showAgentScanner, setShowAgentScanner] = useState(false);

  useEffect(() => {
    fetchEnvironment();
    // Select all resources by default
    if (environment) {
      const allResourceIds = [
        ...environment.vms.map(vm => vm.id),
        ...environment.databases.map(db => db.id),
        ...environment.storage.map(s => s.id),
        ...environment.iam.map(i => i.id),
        ...environment.network.map(n => n.id)
      ];
      setSelectedResources(allResourceIds);
    }
  }, []);

  const fetchEnvironment = async () => {
    try {
      const response = await fetch('/api/environment');
      const data = await response.json();
      setEnvironment(data.environment);
      setTests(data.tests);
      
      // Select all resources by default
      const allResourceIds = [
        ...data.environment.vms.map(vm => vm.id),
        ...data.environment.databases.map(db => db.id),
        ...data.environment.storage.map(s => s.id),
        ...data.environment.iam.map(i => i.id),
        ...data.environment.network.map(n => n.id)
      ];
      setSelectedResources(allResourceIds);
    } catch (error) {
      console.error('Error fetching environment:', error);
    }
  };

  const addResource = async (resourceData) => {
    try {
      const response = await fetch('/api/add-resource', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(resourceData)
      });
      const data = await response.json();
      setEnvironment(data.environment);
      setShowAddResourceModal(false);
      
      // Add new resource to selected resources
      setSelectedResources(prev => [...prev, resourceData.id]);
    } catch (error) {
      console.error('Error adding resource:', error);
    }
  };

  const toggleResourceSelection = (resourceId) => {
    setSelectedResources(prev => 
      prev.includes(resourceId) 
        ? prev.filter(id => id !== resourceId)
        : [...prev, resourceId]
    );
  };

  const selectAllResources = () => {
    const allResourceIds = [
      ...environment.vms.map(vm => vm.id),
      ...environment.databases.map(db => db.id),
      ...environment.storage.map(s => s.id),
      ...environment.iam.map(i => i.id),
      ...environment.network.map(n => n.id)
    ];
    setSelectedResources(allResourceIds);
  };

  const deselectAllResources = () => {
    setSelectedResources([]);
  };

  const startAgentBasedScan = async () => {
    setAgentBasedScanning(true);
    setAgentBasedProgress(0);
    setAgentBasedResults(null);

    const progressInterval = setInterval(() => {
      setAgentBasedProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + 2;
      });
    }, 400);

    try {
      const response = await fetch('/api/scan/agent-based', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selectedResources })
      });
      const data = await response.json();
      clearInterval(progressInterval);
      setAgentBasedProgress(100);
      setAgentBasedResults(data);
      setZeroTrustScore(data.zeroTrustScore);
      setAnomalyDetections(data.anomalyDetections);
      setRuntimeThreats(data.runtimeThreats);
      setAgentBasedScanning(false);
    } catch (error) {
      console.error('Error running agent-based scan:', error);
      clearInterval(progressInterval);
      setAgentBasedScanning(false);
    }
  };

  const startAgentlessScan = async (includeFileChanges = false) => {
    setAgentlessScanning(true);
    setAgentlessProgress(0);
    setAgentlessResults(null);

    const progressInterval = setInterval(() => {
      setAgentlessProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + 6;
      });
    }, 200);

    try {
      const response = await fetch('/api/scan/agentless', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          selectedResources,
          fileSystemChanges: includeFileChanges ? fileSystemChanges : []
        })
      });
      const data = await response.json();
      clearInterval(progressInterval);
      setAgentlessProgress(100);
      setAgentlessResults(data);
      setAgentlessScanning(false);
    } catch (error) {
      console.error('Error running agentless scan:', error);
      clearInterval(progressInterval);
      setAgentlessScanning(false);
    }
  };

  const handleFileSystemChange = (changeType, path, itemName) => {
    const timestamp = new Date().toLocaleString();
    const change = {
      type: changeType,
      path: path.join('/'),
      itemName,
      timestamp,
      id: Date.now()
    };
    
    setFileSystemChanges(prev => [...prev, change]);
    
    // Auto-trigger agentless scan after a short delay
    setTimeout(() => {
      if (agentlessResults) {
        startAgentlessScan(true);
      }
    }, 1000);
  };

  const startBothScans = () => {
    startAgentBasedScan();
    startAgentlessScan();
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'default';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'outline';
    }
  };

  const getResourceIcon = (type) => {
    switch (type) {
      case 'VM': return <Server className="h-4 w-4" />;
      case 'Database': return <Database className="h-4 w-4" />;
      case 'Storage': return <HardDrive className="h-4 w-4" />;
      case 'IAM Role': return <Users className="h-4 w-4" />;
      case 'Security Group': return <Network className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const openVulnerabilityDetail = (finding) => {
    setSelectedVulnerability(finding);
    setShowDetailModal(true);
  };

  // Get similarities and differences
  const getComparisonAnalysis = () => {
    if (!agentBasedResults || !agentlessResults) return null;

    const agentVulns = new Set(agentBasedResults.findings.map(f => `${f.resourceId}-${f.vulnerability}`));
    const agentlessVulns = new Set(agentlessResults.findings.map(f => `${f.resourceId}-${f.vulnerability}`));

    const bothDetected = [];
    const agentOnlyDetected = [];
    const agentlessOnlyDetected = [];

    agentBasedResults.findings.forEach(f => {
      const key = `${f.resourceId}-${f.vulnerability}`;
      if (agentlessVulns.has(key)) {
        bothDetected.push(f);
      } else {
        agentOnlyDetected.push(f);
      }
    });

    agentlessResults.findings.forEach(f => {
      const key = `${f.resourceId}-${f.vulnerability}`;
      if (!agentVulns.has(key)) {
        agentlessOnlyDetected.push(f);
      }
    });

    return { bothDetected, agentOnlyDetected, agentlessOnlyDetected };
  };

  const comparison = getComparisonAnalysis();

  const exportResults = (type) => {
    const data = type === 'agent-based' ? agentBasedResults : agentlessResults;
    const dataStr = JSON.stringify(data, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${type}-scan-results-${new Date().toISOString()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <div className="border-b bg-white/50 dark:bg-slate-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                <Shield className="h-8 w-8 text-blue-600" />
                Cloud Security Platform
              </h1>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                Comprehensive security scanning and vulnerability detection
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button 
                onClick={() => {
                  setShowDashboard(!showDashboard);
                  setShowAgentScanner(false);
                }} 
                variant={showDashboard ? "default" : "outline"} 
                size="sm" 
                className="gap-2"
              >
                <Info className="h-4 w-4" />
                Dashboard
              </Button>
              <Button 
                onClick={() => setShowAddResourceModal(true)} 
                variant="outline" 
                size="sm" 
                className="gap-2"
              >
                <Settings className="h-4 w-4" />
                Add Resource
              </Button>
              <Button 
                onClick={() => setShowResourceSelector(!showResourceSelector)} 
                variant="outline" 
                size="sm" 
                className="gap-2"
              >
                <Eye className="h-4 w-4" />
                Select Resources ({selectedResources.length})
              </Button>
              <Button 
                onClick={() => setShowWindowsEnv(true)} 
                variant="outline" 
                size="sm" 
                className="gap-2"
              >
                <Monitor className="h-4 w-4" />
                Cloud Preview
              </Button>
              <Button 
                onClick={() => {
                  setShowAgentScanner(!showAgentScanner);
                  setShowDashboard(false);
                }} 
                variant={showAgentScanner ? "default" : "outline"} 
                size="sm" 
                className="gap-2 bg-purple-50 hover:bg-purple-100 dark:bg-purple-950 dark:hover:bg-purple-900 border-purple-200"
              >
                <Terminal className="h-4 w-4" />
                Agentless Scanner
              </Button>
              <Button 
                onClick={startBothScans} 
                size="sm" 
                className="gap-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700" 
                disabled={agentBasedScanning || agentlessScanning || selectedResources.length === 0}
              >
                <Zap className="h-4 w-4" />
                Run Both Scans
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Agent Scanner View */}
        {showAgentScanner && (
          <div className="mb-8">
            <AgentScanner />
          </div>
        )}

        {/* Cloud Environment Overview */}
        {!showAgentScanner && environment && (
          <Card className="mb-8 border-2">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Settings className="h-5 w-5" />
                    Simulated Cloud Environment
                  </CardTitle>
                  <CardDescription>
                    A realistic multi-service cloud infrastructure with intentional vulnerabilities for security testing
                  </CardDescription>
                </div>
                {selectedResources.length > 0 && (
                  <Badge variant="default" className="text-lg px-4 py-2">
                    {selectedResources.length} / {
                      environment.vms.length + 
                      environment.databases.length + 
                      environment.storage.length + 
                      environment.iam.length + 
                      environment.network.length
                    } Resources Selected
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                  <Server className="h-8 w-8 mx-auto mb-2 text-blue-600" />
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{environment.vms.length}</div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Virtual Machines</div>
                </div>
                <div className="text-center p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <Database className="h-8 w-8 mx-auto mb-2 text-green-600" />
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{environment.databases.length}</div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Databases</div>
                </div>
                <div className="text-center p-4 bg-purple-50 dark:bg-purple-950 rounded-lg">
                  <HardDrive className="h-8 w-8 mx-auto mb-2 text-purple-600" />
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{environment.storage.length}</div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Storage Buckets</div>
                </div>
                <div className="text-center p-4 bg-orange-50 dark:bg-orange-950 rounded-lg">
                  <Users className="h-8 w-8 mx-auto mb-2 text-orange-600" />
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{environment.iam.length}</div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">IAM Roles</div>
                </div>
                <div className="text-center p-4 bg-red-50 dark:bg-red-950 rounded-lg">
                  <Network className="h-8 w-8 mx-auto mb-2 text-red-600" />
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{environment.network.length}</div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Security Groups</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Advanced Security Features */}
        {!showAgentScanner && (zeroTrustScore || anomalyDetections || runtimeThreats) && (
          <div className="grid md:grid-cols-3 gap-6 mb-8">
            {/* Zero Trust Security */}
            {zeroTrustScore && (
              <Card className="border-2 border-indigo-200 dark:border-indigo-800 cursor-pointer hover:shadow-lg transition-shadow" onClick={() => setShowZeroTrustDetail(true)}>
                <CardHeader className="bg-indigo-50 dark:bg-indigo-950 pb-3">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Lock className="h-5 w-5 text-indigo-600" />
                    Zero Trust Security
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Never trust, always verify approach • Click for details
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4">
                  <div className="space-y-4">
                    <div className="text-center">
                      <div className={`text-4xl font-bold mb-2 ${
                        zeroTrustScore.score >= 80 ? 'text-green-600' :
                        zeroTrustScore.score >= 60 ? 'text-yellow-600' :
                        'text-red-600'
                      }`}>
                        {zeroTrustScore.score}%
                      </div>
                      <p className="text-sm text-slate-600 dark:text-slate-400">
                        Zero Trust Compliance Score
                      </p>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-600 dark:text-slate-400">Identity Verification</span>
                        <span className={`font-semibold ${zeroTrustScore.identityVerification >= 70 ? 'text-green-600' : 'text-red-600'}`}>
                          {zeroTrustScore.identityVerification}%
                        </span>
                      </div>
                      <Progress value={zeroTrustScore.identityVerification} className="h-2" />
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-600 dark:text-slate-400">Device Trust</span>
                        <span className={`font-semibold ${zeroTrustScore.deviceTrust >= 70 ? 'text-green-600' : 'text-red-600'}`}>
                          {zeroTrustScore.deviceTrust}%
                        </span>
                      </div>
                      <Progress value={zeroTrustScore.deviceTrust} className="h-2" />
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-600 dark:text-slate-400">Network Segmentation</span>
                        <span className={`font-semibold ${zeroTrustScore.networkSegmentation >= 70 ? 'text-green-600' : 'text-red-600'}`}>
                          {zeroTrustScore.networkSegmentation}%
                        </span>
                      </div>
                      <Progress value={zeroTrustScore.networkSegmentation} className="h-2" />
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-600 dark:text-slate-400">Least Privilege Access</span>
                        <span className={`font-semibold ${zeroTrustScore.leastPrivilege >= 70 ? 'text-green-600' : 'text-red-600'}`}>
                          {zeroTrustScore.leastPrivilege}%
                        </span>
                      </div>
                      <Progress value={zeroTrustScore.leastPrivilege} className="h-2" />
                    </div>

                    <Alert className="mt-4">
                      <Lock className="h-4 w-4" />
                      <AlertTitle className="text-xs">Zero Trust Model</AlertTitle>
                      <AlertDescription className="text-xs">
                        {zeroTrustScore.findings.length} security gaps identified in zero trust implementation
                      </AlertDescription>
                    </Alert>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Anomaly Detection */}
            {anomalyDetections && (
              <Card className="border-2 border-purple-200 dark:border-purple-800 cursor-pointer hover:shadow-lg transition-shadow" onClick={() => setShowAnomalyDetail(true)}>
                <CardHeader className="bg-purple-50 dark:bg-purple-950 pb-3">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Activity className="h-5 w-5 text-purple-600" />
                    Anomaly Detection
                  </CardTitle>
                  <CardDescription className="text-xs">
                    AI-powered behavioral analysis • Click for details
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <div className="text-center p-3 bg-purple-50 dark:bg-purple-950 rounded-lg">
                        <div className="text-2xl font-bold text-purple-600">{anomalyDetections.total}</div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">Anomalies Detected</div>
                      </div>
                      <div className="text-center p-3 bg-red-50 dark:bg-red-950 rounded-lg">
                        <div className="text-2xl font-bold text-red-600">{anomalyDetections.critical}</div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">Critical Alerts</div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      {anomalyDetections.types.map((type, idx) => (
                        <div key={idx} className="p-2 border rounded-lg bg-white dark:bg-slate-900">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-medium">{type.name}</span>
                            <Badge variant={type.severity === 'high' ? 'destructive' : 'secondary'} className="text-xs">
                              {type.count}
                            </Badge>
                          </div>
                          <p className="text-xs text-slate-600 dark:text-slate-400">{type.description}</p>
                        </div>
                      ))}
                    </div>

                    <Alert>
                      <Activity className="h-4 w-4" />
                      <AlertTitle className="text-xs">ML-Based Detection</AlertTitle>
                      <AlertDescription className="text-xs">
                        Using machine learning to identify unusual patterns and potential threats
                      </AlertDescription>
                    </Alert>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Runtime Detection */}
            {runtimeThreats && (
              <Card className="border-2 border-amber-200 dark:border-amber-800 cursor-pointer hover:shadow-lg transition-shadow" onClick={() => setShowRuntimeDetail(true)}>
                <CardHeader className="bg-amber-50 dark:bg-amber-950 pb-3">
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <PlayCircle className="h-5 w-5 text-amber-600" />
                    Runtime Detection
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Real-time threat monitoring • Click for details
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <div className="text-center p-3 bg-amber-50 dark:bg-amber-950 rounded-lg">
                        <div className="text-2xl font-bold text-amber-600">{runtimeThreats.activeThreats}</div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">Active Threats</div>
                      </div>
                      <div className="text-center p-3 bg-green-50 dark:bg-green-950 rounded-lg">
                        <div className="text-2xl font-bold text-green-600">{runtimeThreats.blocked}</div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">Threats Blocked</div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      {runtimeThreats.categories.map((cat, idx) => (
                        <div key={idx} className="flex items-start gap-2 p-2 border rounded-lg bg-white dark:bg-slate-900">
                          <AlertTriangle className={`h-4 w-4 mt-0.5 ${
                            cat.risk === 'critical' ? 'text-red-600' : 
                            cat.risk === 'high' ? 'text-orange-600' : 
                            'text-yellow-600'
                          }`} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-medium">{cat.name}</span>
                              <Badge variant={cat.risk === 'critical' ? 'destructive' : 'secondary'} className="text-xs">
                                {cat.count}
                              </Badge>
                            </div>
                            <p className="text-xs text-slate-600 dark:text-slate-400">{cat.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>

                    <Alert>
                      <PlayCircle className="h-4 w-4" />
                      <AlertTitle className="text-xs">Real-Time Protection</AlertTitle>
                      <AlertDescription className="text-xs">
                        Monitoring {runtimeThreats.monitoredProcesses} processes across {runtimeThreats.monitoredResources} resources
                      </AlertDescription>
                    </Alert>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Side-by-Side Comparison */}
        {!showAgentScanner && (<>
        <div className="grid md:grid-cols-2 gap-8 mb-8">
          {/* Agent-Based Tool */}
          <Card className="border-2 border-blue-200 dark:border-blue-800">
            <CardHeader className="bg-blue-50 dark:bg-blue-950">
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-600" />
                  Agent-Based Security Tool
                </span>
                <div className="flex gap-2">
                  {agentBasedResults && (
                    <Button onClick={() => exportResults('agent-based')} size="sm" variant="outline" className="gap-2">
                      <Download className="h-4 w-4" />
                      Export
                    </Button>
                  )}
                  <Button onClick={startAgentBasedScan} disabled={agentBasedScanning || selectedResources.length === 0} size="sm">
                    {agentBasedScanning ? 'Scanning...' : 'Start Scan'}
                  </Button>
                </div>
              </CardTitle>
              <CardDescription>Deep inspection with installed agents on each resource</CardDescription>
            </CardHeader>
            <CardContent className="pt-6">
              {agentBasedScanning && (
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Scanning Progress</span>
                    <span className="text-sm text-slate-600 dark:text-slate-400">{agentBasedProgress}%</span>
                  </div>
                  <Progress value={agentBasedProgress} className="h-2" />
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">Deep inspection in progress...</p>
                </div>
              )}

              {agentBasedResults && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-50 dark:bg-slate-800 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-slate-900 dark:text-white">{agentBasedResults.stats.vulnerabilitiesFound}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Vulnerabilities Found</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-800 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-slate-900 dark:text-white">{(agentBasedResults.stats.scanTime / 1000).toFixed(1)}s</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Scan Time</div>
                    </div>
                    <div className="bg-red-50 dark:bg-red-950 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">{agentBasedResults.stats.criticalIssues}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Critical Issues</div>
                    </div>
                    <div className="bg-orange-50 dark:bg-orange-950 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-orange-600">{agentBasedResults.stats.highIssues}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">High Issues</div>
                    </div>
                  </div>

                  <div className="border-t pt-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Detection Rate</span>
                      <span className="text-lg font-bold text-green-600">{agentBasedResults.stats.detectionRate}%</span>
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Avg Risk Score</span>
                      <span className="text-sm font-bold">{agentBasedResults.stats.avgRiskScore}/100</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Tests Run</span>
                      <span className="text-sm font-bold">{agentBasedResults.stats.testsRun}/10</span>
                    </div>
                  </div>

                  <Alert>
                    <Settings className="h-4 w-4" />
                    <AlertTitle>Deployment Complexity</AlertTitle>
                    <AlertDescription className="text-xs">
                      Requires agent installation on each resource. Higher overhead but deeper inspection capabilities.
                    </AlertDescription>
                  </Alert>
                </div>
              )}

              {!agentBasedScanning && !agentBasedResults && (
                <div className="text-center py-8 text-slate-500">
                  <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">Click "Start Scan" to begin agent-based security analysis</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Agentless Tool */}
          <Card className="border-2 border-green-200 dark:border-green-800">
            <CardHeader className="bg-green-50 dark:bg-green-950">
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-green-600" />
                  Agentless Security Tool
                </span>
                <div className="flex gap-2">
                  {agentlessResults && (
                    <Button onClick={() => exportResults('agentless')} size="sm" variant="outline" className="gap-2">
                      <Download className="h-4 w-4" />
                      Export
                    </Button>
                  )}
                  <Button onClick={startAgentlessScan} disabled={agentlessScanning || selectedResources.length === 0} size="sm" variant="outline">
                    {agentlessScanning ? 'Scanning...' : 'Start Scan'}
                  </Button>
                </div>
              </CardTitle>
              <CardDescription>API-based scanning without agent installation</CardDescription>
            </CardHeader>
            <CardContent className="pt-6">
              {agentlessScanning && (
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Scanning Progress</span>
                    <span className="text-sm text-slate-600 dark:text-slate-400">{agentlessProgress}%</span>
                  </div>
                  <Progress value={agentlessProgress} className="h-2" />
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">API-based scan in progress...</p>
                </div>
              )}

              {agentlessResults && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-50 dark:bg-slate-800 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-slate-900 dark:text-white">{agentlessResults.stats.vulnerabilitiesFound}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Vulnerabilities Found</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-800 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-slate-900 dark:text-white">{(agentlessResults.stats.scanTime / 1000).toFixed(1)}s</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Scan Time</div>
                    </div>
                    <div className="bg-red-50 dark:bg-red-950 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">{agentlessResults.stats.criticalIssues}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">Critical Issues</div>
                    </div>
                    <div className="bg-orange-50 dark:bg-orange-950 p-3 rounded-lg">
                      <div className="text-2xl font-bold text-orange-600">{agentlessResults.stats.highIssues}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">High Issues</div>
                    </div>
                  </div>

                  <div className="border-t pt-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Detection Rate</span>
                      <span className="text-lg font-bold text-yellow-600">{agentlessResults.stats.detectionRate}%</span>
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Avg Risk Score</span>
                      <span className="text-sm font-bold">{agentlessResults.stats.avgRiskScore}/100</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Tests Run</span>
                      <span className="text-sm font-bold">{agentlessResults.stats.testsRun}/10</span>
                    </div>
                  </div>

                  <Alert>
                    <Zap className="h-4 w-4" />
                    <AlertTitle>Deployment Complexity</AlertTitle>
                    <AlertDescription className="text-xs">
                      No agent installation required. API permissions only. Faster but limited inspection depth.
                    </AlertDescription>
                  </Alert>
                </div>
              )}

              {!agentlessScanning && !agentlessResults && (
                <div className="text-center py-8 text-slate-500">
                  <Zap className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">Click "Start Scan" to begin agentless security analysis</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Similarities and Differences */}
        {!showAgentScanner && comparison && (
          <Card className="mb-8 border-2 border-purple-200 dark:border-purple-800">
            <CardHeader className="bg-purple-50 dark:bg-purple-950">
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5" />
                Detection Comparison: Similarities & Differences
              </CardTitle>
              <CardDescription>Analysis of what each tool detected</CardDescription>
            </CardHeader>
            <CardContent className="pt-6">
              <div className="grid md:grid-cols-3 gap-4">
                <div className="border-2 border-green-200 dark:border-green-800 rounded-lg p-4 bg-green-50/50 dark:bg-green-950/50">
                  <div className="flex items-center gap-2 mb-3">
                    <CheckCircle className="h-5 w-5 text-green-600" />
                    <h3 className="font-semibold text-green-900 dark:text-green-100">Both Detected</h3>
                  </div>
                  <div className="text-3xl font-bold text-green-600 mb-1">{comparison.bothDetected.length}</div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mb-3">
                    Vulnerabilities detected by both tools (common ground)
                  </p>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {comparison.bothDetected.slice(0, 5).map((f, idx) => (
                      <div key={idx} className="text-xs p-2 bg-white dark:bg-slate-900 rounded border">
                        <span className="font-medium">{f.resourceName}</span>
                        <Badge variant="outline" className="ml-2 text-xs">{f.severity}</Badge>
                      </div>
                    ))}
                    {comparison.bothDetected.length > 5 && (
                      <p className="text-xs text-slate-500 text-center pt-1">+{comparison.bothDetected.length - 5} more</p>
                    )}
                  </div>
                </div>

                <div className="border-2 border-blue-200 dark:border-blue-800 rounded-lg p-4 bg-blue-50/50 dark:bg-blue-950/50">
                  <div className="flex items-center gap-2 mb-3">
                    <Shield className="h-5 w-5 text-blue-600" />
                    <h3 className="font-semibold text-blue-900 dark:text-blue-100">Agent-Based Only</h3>
                  </div>
                  <div className="text-3xl font-bold text-blue-600 mb-1">{comparison.agentOnlyDetected.length}</div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mb-3">
                    Vulnerabilities only agent-based tool found (advantage)
                  </p>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {comparison.agentOnlyDetected.slice(0, 5).map((f, idx) => (
                      <div key={idx} className="text-xs p-2 bg-white dark:bg-slate-900 rounded border border-blue-200">
                        <span className="font-medium">{f.resourceName}</span>
                        <Badge variant="destructive" className="ml-2 text-xs">{f.severity}</Badge>
                        <p className="text-xs text-slate-500 mt-1 truncate">{f.vulnerabilityTitle}</p>
                      </div>
                    ))}
                    {comparison.agentOnlyDetected.length > 5 && (
                      <p className="text-xs text-slate-500 text-center pt-1">+{comparison.agentOnlyDetected.length - 5} more</p>
                    )}
                  </div>
                </div>

                <div className="border-2 border-amber-200 dark:border-amber-800 rounded-lg p-4 bg-amber-50/50 dark:bg-amber-950/50">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="h-5 w-5 text-amber-600" />
                    <h3 className="font-semibold text-amber-900 dark:text-amber-100">Missed by Agentless</h3>
                  </div>
                  <div className="text-3xl font-bold text-amber-600 mb-1">{comparison.agentOnlyDetected.length}</div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mb-3">
                    Critical vulnerabilities agentless tool cannot detect
                  </p>
                  <div className="bg-amber-100 dark:bg-amber-900/30 p-3 rounded border border-amber-200 dark:border-amber-800">
                    <p className="text-xs font-semibold mb-2">Common Blind Spots:</p>
                    <ul className="text-xs space-y-1 text-slate-700 dark:text-slate-300">
                      <li>• In-memory threats</li>
                      <li>• Weak/default passwords</li>
                      <li>• Suspicious processes</li>
                      <li>• Rootkit detection</li>
                      <li>• Exposed API keys in files</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Comparison Chart */}
        {agentBasedResults && agentlessResults && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Performance & Detection Comparison</CardTitle>
              <CardDescription>Side-by-side comparison of key metrics</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-3 gap-6">
                <div>
                  <h3 className="font-semibold mb-4 text-center">Detection Coverage</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agent-Based</span>
                        <span className="text-sm font-bold text-blue-600">{agentBasedResults.stats.detectionRate}%</span>
                      </div>
                      <Progress value={agentBasedResults.stats.detectionRate} className="h-3 bg-blue-100" />
                      <p className="text-xs text-slate-500 mt-1">{agentBasedResults.stats.vulnerabilitiesFound} vulnerabilities</p>
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agentless</span>
                        <span className="text-sm font-bold text-green-600">{agentlessResults.stats.detectionRate}%</span>
                      </div>
                      <Progress value={agentlessResults.stats.detectionRate} className="h-3 bg-green-100" />
                      <p className="text-xs text-slate-500 mt-1">{agentlessResults.stats.vulnerabilitiesFound} vulnerabilities</p>
                    </div>
                    <div className="pt-2 border-t">
                      <div className="flex items-center gap-2 text-xs text-amber-600">
                        <AlertTriangle className="h-3 w-3" />
                        <span>{agentBasedResults.stats.vulnerabilitiesFound - agentlessResults.stats.vulnerabilitiesFound} vulnerabilities missed by agentless</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold mb-4 text-center">Scan Speed</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agent-Based</span>
                        <span className="text-sm font-bold text-blue-600">{(agentBasedResults.stats.scanTime / 1000).toFixed(1)}s</span>
                      </div>
                      <div className="h-3 bg-blue-100 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-blue-600" 
                          style={{ width: `${(agentBasedResults.stats.scanTime / Math.max(agentBasedResults.stats.scanTime, agentlessResults.stats.scanTime)) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agentless</span>
                        <span className="text-sm font-bold text-green-600">{(agentlessResults.stats.scanTime / 1000).toFixed(1)}s</span>
                      </div>
                      <div className="h-3 bg-green-100 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-green-600" 
                          style={{ width: `${(agentlessResults.stats.scanTime / Math.max(agentBasedResults.stats.scanTime, agentlessResults.stats.scanTime)) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    <div className="pt-2 border-t">
                      <div className="flex items-center gap-2 text-xs text-green-600">
                        <CheckCircle className="h-3 w-3" />
                        <span>Agentless is {((agentBasedResults.stats.scanTime / agentlessResults.stats.scanTime)).toFixed(1)}x faster</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold mb-4 text-center">Test Coverage</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agent-Based</span>
                        <span className="text-sm font-bold text-blue-600">{agentBasedResults.stats.testsRun}/10</span>
                      </div>
                      <Progress value={(agentBasedResults.stats.testsRun / 10) * 100} className="h-3 bg-blue-100" />
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Agentless</span>
                        <span className="text-sm font-bold text-green-600">{agentlessResults.stats.testsRun}/10</span>
                      </div>
                      <Progress value={(agentlessResults.stats.testsRun / 10) * 100} className="h-3 bg-green-100" />
                    </div>
                    <div className="pt-2 border-t">
                      <div className="text-xs text-slate-600">
                        Agent-based can run all security tests including deep inspection tests.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Detailed Findings */}
        {!showAgentScanner && (agentBasedResults || agentlessResults) && (
          <Card>
            <CardHeader>
              <CardTitle>Detailed Security Findings</CardTitle>
              <CardDescription>Click on any vulnerability to view detailed information</CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="agent-based" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="agent-based" disabled={!agentBasedResults}>
                    Agent-Based ({agentBasedResults?.findings?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="agentless" disabled={!agentlessResults}>
                    Agentless ({agentlessResults?.findings?.length || 0})
                  </TabsTrigger>
                </TabsList>
                <TabsContent value="agent-based" className="mt-4">
                  {agentBasedResults && (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {agentBasedResults.findings.map((finding, idx) => (
                        <div 
                          key={idx} 
                          className="flex items-start gap-3 p-3 border rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                          onClick={() => openVulnerabilityDetail(finding)}
                        >
                          <div className="mt-1">{getResourceIcon(finding.resourceType)}</div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-medium text-sm">{finding.resourceName}</span>
                              <Badge variant={getSeverityColor(finding.severity)} className="text-xs">
                                {finding.severity}
                              </Badge>
                              <Badge variant="outline" className="text-xs">{finding.resourceType}</Badge>
                              {finding.cvss && (
                                <Badge variant="secondary" className="text-xs">CVSS: {finding.cvss}</Badge>
                              )}
                            </div>
                            <p className="text-xs text-slate-600 dark:text-slate-400">{finding.description}</p>
                          </div>
                          <Info className="h-4 w-4 text-slate-400 flex-shrink-0" />
                        </div>
                      ))}
                    </div>
                  )}
                </TabsContent>
                <TabsContent value="agentless" className="mt-4">
                  {agentlessResults && (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {agentlessResults.findings.map((finding, idx) => (
                        <div 
                          key={idx} 
                          className="flex items-start gap-3 p-3 border rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                          onClick={() => openVulnerabilityDetail(finding)}
                        >
                          <div className="mt-1">{getResourceIcon(finding.resourceType)}</div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-medium text-sm">{finding.resourceName}</span>
                              <Badge variant={getSeverityColor(finding.severity)} className="text-xs">
                                {finding.severity}
                              </Badge>
                              <Badge variant="outline" className="text-xs">{finding.resourceType}</Badge>
                              {finding.cvss && (
                                <Badge variant="secondary" className="text-xs">CVSS: {finding.cvss}</Badge>
                              )}
                            </div>
                            <p className="text-xs text-slate-600 dark:text-slate-400">{finding.description}</p>
                          </div>
                          <Info className="h-4 w-4 text-slate-400 flex-shrink-0" />
                        </div>
                      ))}
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
        </>)}
      </div>

      {/* Resource Selector Panel */}
      {showResourceSelector && environment && (
        <div className="fixed top-20 right-4 w-96 max-h-[80vh] overflow-y-auto bg-white dark:bg-slate-900 rounded-lg shadow-2xl border-2 border-slate-200 dark:border-slate-700 z-50">
          <div className="p-4 border-b sticky top-0 bg-white dark:bg-slate-900">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-bold text-lg">Select Resources to Scan</h3>
              <Button variant="ghost" size="sm" onClick={() => setShowResourceSelector(false)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={selectAllResources} className="flex-1">
                Select All
              </Button>
              <Button variant="outline" size="sm" onClick={deselectAllResources} className="flex-1">
                Deselect All
              </Button>
            </div>
          </div>

          <div className="p-4 space-y-4">
            {/* Virtual Machines */}
            <div>
              <h4 className="font-semibold text-sm mb-2 flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-600" />
                Virtual Machines ({environment.vms.length})
              </h4>
              <div className="space-y-2">
                {environment.vms.map(vm => (
                  <label key={vm.id} className="flex items-start gap-3 p-2 hover:bg-slate-50 dark:hover:bg-slate-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedResources.includes(vm.id)}
                      onChange={() => toggleResourceSelection(vm.id)}
                      className="mt-1"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{vm.name}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">
                        {vm.os} • {vm.region} • {vm.instanceType}
                      </div>
                      <div className="text-xs text-red-600 mt-1">
                        {vm.vulnerabilities.length} vulnerabilities
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Databases */}
            <div>
              <h4 className="font-semibold text-sm mb-2 flex items-center gap-2">
                <Database className="h-4 w-4 text-green-600" />
                Databases ({environment.databases.length})
              </h4>
              <div className="space-y-2">
                {environment.databases.map(db => (
                  <label key={db.id} className="flex items-start gap-3 p-2 hover:bg-slate-50 dark:hover:bg-slate-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedResources.includes(db.id)}
                      onChange={() => toggleResourceSelection(db.id)}
                      className="mt-1"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{db.name}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">
                        {db.type} {db.version} • {db.connections} connections
                      </div>
                      <div className="text-xs text-red-600 mt-1">
                        {db.vulnerabilities.length} vulnerabilities
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Storage */}
            <div>
              <h4 className="font-semibold text-sm mb-2 flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-purple-600" />
                Storage Buckets ({environment.storage.length})
              </h4>
              <div className="space-y-2">
                {environment.storage.map(bucket => (
                  <label key={bucket.id} className="flex items-start gap-3 p-2 hover:bg-slate-50 dark:hover:bg-slate-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedResources.includes(bucket.id)}
                      onChange={() => toggleResourceSelection(bucket.id)}
                      className="mt-1"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{bucket.name}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">
                        {bucket.size} • {bucket.objects} objects • {bucket.public ? 'Public' : 'Private'}
                      </div>
                      <div className="text-xs text-red-600 mt-1">
                        {bucket.vulnerabilities.length} vulnerabilities
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* IAM Roles */}
            <div>
              <h4 className="font-semibold text-sm mb-2 flex items-center gap-2">
                <Users className="h-4 w-4 text-orange-600" />
                IAM Roles ({environment.iam.length})
              </h4>
              <div className="space-y-2">
                {environment.iam.map(role => (
                  <label key={role.id} className="flex items-start gap-3 p-2 hover:bg-slate-50 dark:hover:bg-slate-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedResources.includes(role.id)}
                      onChange={() => toggleResourceSelection(role.id)}
                      className="mt-1"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{role.name}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">
                        {role.users} users • Last used: {role.lastUsed}
                      </div>
                      <div className="text-xs text-red-600 mt-1">
                        {role.vulnerabilities.length} vulnerabilities
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Security Groups */}
            <div>
              <h4 className="font-semibold text-sm mb-2 flex items-center gap-2">
                <Network className="h-4 w-4 text-red-600" />
                Security Groups ({environment.network.length})
              </h4>
              <div className="space-y-2">
                {environment.network.map(sg => (
                  <label key={sg.id} className="flex items-start gap-3 p-2 hover:bg-slate-50 dark:hover:bg-slate-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedResources.includes(sg.id)}
                      onChange={() => toggleResourceSelection(sg.id)}
                      className="mt-1"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{sg.name}</div>
                      <div className="text-xs text-slate-600 dark:text-slate-400">
                        {sg.rules.length} rules • {sg.attachedResources} attached resources
                      </div>
                      <div className="text-xs text-red-600 mt-1">
                        {sg.vulnerabilities.length} vulnerabilities
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Resource Modal */}
      <Dialog open={showAddResourceModal} onOpenChange={setShowAddResourceModal}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Add New Resource</DialogTitle>
            <DialogDescription>
              Create a new virtual machine, database, or storage bucket for security scanning
            </DialogDescription>
          </DialogHeader>
          <AddResourceForm 
            resourceType={resourceType}
            setResourceType={setResourceType}
            onSubmit={addResource}
            onCancel={() => setShowAddResourceModal(false)}
          />
        </DialogContent>
      </Dialog>

      {/* Vulnerability Detail Modal */}
      <Dialog open={showDetailModal} onOpenChange={setShowDetailModal}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          {selectedVulnerability && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3 text-xl">
                  <AlertTriangle className="h-6 w-6 text-red-600" />
                  {selectedVulnerability.vulnerabilityTitle}
                </DialogTitle>
                <DialogDescription>
                  Detailed vulnerability analysis and remediation steps
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
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">Severity</div>
                      <Badge variant={getSeverityColor(selectedVulnerability.severity)} className="text-sm">
                        {selectedVulnerability.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">CVSS Score</div>
                      <div className="text-lg font-bold">{selectedVulnerability.cvss}</div>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">Risk Score</div>
                      <div className="text-lg font-bold">{selectedVulnerability.riskScore}/100</div>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                      <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">Detected By</div>
                      <div className="text-sm font-medium capitalize">{selectedVulnerability.detectedBy}</div>
                    </div>
                  </div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">{selectedVulnerability.description}</p>
                </div>

                {/* Resource Details */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    {getResourceIcon(selectedVulnerability.resourceType)}
                    Affected Resource
                  </h3>
                  <div className="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-slate-600 dark:text-slate-400">Resource:</span>
                        <span className="ml-2 font-medium">{selectedVulnerability.resourceName}</span>
                      </div>
                      <div>
                        <span className="text-slate-600 dark:text-slate-400">Type:</span>
                        <span className="ml-2 font-medium">{selectedVulnerability.resourceType}</span>
                      </div>
                      {Object.entries(selectedVulnerability.resourceDetails || {}).map(([key, value]) => (
                        <div key={key}>
                          <span className="text-slate-600 dark:text-slate-400 capitalize">{key.replace(/([A-Z])/g, ' $1')}:</span>
                          <span className="ml-2 font-medium">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* CVE References */}
                {selectedVulnerability.cve && selectedVulnerability.cve.length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-3">CVE References</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedVulnerability.cve.map((cve, idx) => (
                        <Badge key={idx} variant="outline" className="text-xs">{cve}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Impact */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-orange-600" />
                    Impact
                  </h3>
                  <div className="p-4 bg-orange-50 dark:bg-orange-950 rounded-lg border border-orange-200 dark:border-orange-800">
                    <p className="text-sm text-slate-700 dark:text-slate-300">{selectedVulnerability.impact}</p>
                  </div>
                </div>

                {/* Remediation */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-600" />
                    Remediation Steps
                  </h3>
                  <div className="space-y-2">
                    {selectedVulnerability.remediation?.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2 p-3 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                        <div className="flex-shrink-0 w-6 h-6 bg-green-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                          {idx + 1}
                        </div>
                        <p className="text-sm text-slate-700 dark:text-slate-300 flex-1">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Compliance Impact */}
                {selectedVulnerability.complianceImpact && selectedVulnerability.complianceImpact.length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-3">Compliance Impact</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedVulnerability.complianceImpact.map((comp, idx) => (
                        <Badge key={idx} variant="secondary">{comp}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Zero Trust Detail Modal */}
      <Dialog open={showZeroTrustDetail} onOpenChange={setShowZeroTrustDetail}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          {zeroTrustScore && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3 text-xl">
                  <Lock className="h-6 w-6 text-indigo-600" />
                  Zero Trust Security Analysis
                </DialogTitle>
                <DialogDescription>
                  Comprehensive zero trust security model evaluation
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-6 pt-4">
                {/* Overall Score */}
                <div className="text-center p-6 bg-indigo-50 dark:bg-indigo-950 rounded-lg border-2 border-indigo-200 dark:border-indigo-800">
                  <div className={`text-6xl font-bold mb-2 ${
                    zeroTrustScore.score >= 80 ? 'text-green-600' :
                    zeroTrustScore.score >= 60 ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {zeroTrustScore.score}%
                  </div>
                  <p className="text-lg font-semibold text-slate-700 dark:text-slate-300">
                    Zero Trust Compliance Score
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">
                    {zeroTrustScore.score >= 80 ? 'Excellent zero trust implementation' :
                     zeroTrustScore.score >= 60 ? 'Good but needs improvement' :
                     'Critical gaps in zero trust model'}
                  </p>
                </div>

                {/* Detailed Metrics */}
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-indigo-600" />
                      Identity Verification
                    </h3>
                    <Progress value={zeroTrustScore.identityVerification} className="h-3 mb-2" />
                    <p className="text-2xl font-bold mb-1">{zeroTrustScore.identityVerification}%</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Measures strength of identity verification, MFA implementation, and authentication controls
                    </p>
                  </div>

                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Server className="h-4 w-4 text-indigo-600" />
                      Device Trust
                    </h3>
                    <Progress value={zeroTrustScore.deviceTrust} className="h-3 mb-2" />
                    <p className="text-2xl font-bold mb-1">{zeroTrustScore.deviceTrust}%</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Evaluates device security posture, patching, antivirus, and endpoint protection
                    </p>
                  </div>

                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Network className="h-4 w-4 text-indigo-600" />
                      Network Segmentation
                    </h3>
                    <Progress value={zeroTrustScore.networkSegmentation} className="h-3 mb-2" />
                    <p className="text-2xl font-bold mb-1">{zeroTrustScore.networkSegmentation}%</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Assesses network isolation, micro-segmentation, and access controls
                    </p>
                  </div>

                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                      <Users className="h-4 w-4 text-indigo-600" />
                      Least Privilege Access
                    </h3>
                    <Progress value={zeroTrustScore.leastPrivilege} className="h-3 mb-2" />
                    <p className="text-2xl font-bold mb-1">{zeroTrustScore.leastPrivilege}%</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Reviews permission assignments, privilege escalation risks, and access policies
                    </p>
                  </div>
                </div>

                {/* Findings */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-orange-600" />
                    Zero Trust Security Gaps ({zeroTrustScore.findings.length})
                  </h3>
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {zeroTrustScore.findings.map((finding, idx) => (
                      <div key={idx} className="p-3 border rounded-lg bg-slate-50 dark:bg-slate-900">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <Badge variant="outline" className="mb-1">{finding.category}</Badge>
                            <p className="font-medium text-sm">{finding.issue}</p>
                            <p className="text-xs text-slate-600 dark:text-slate-400">Resource: {finding.resource}</p>
                          </div>
                          <Badge variant={finding.severity === 'critical' ? 'destructive' : 'default'}>
                            {finding.severity}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommendations */}
                <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-green-600" />
                    Recommendations for Zero Trust Implementation
                  </h3>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-start gap-2">
                      <span className="text-green-600">•</span>
                      <span>Implement multi-factor authentication (MFA) for all users and services</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-green-600">•</span>
                      <span>Enforce device health checks before granting access</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-green-600">•</span>
                      <span>Implement network micro-segmentation to limit lateral movement</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-green-600">•</span>
                      <span>Apply principle of least privilege across all IAM policies</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-green-600">•</span>
                      <span>Enable continuous monitoring and adaptive access controls</span>
                    </li>
                  </ul>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Anomaly Detection Detail Modal */}
      <Dialog open={showAnomalyDetail} onOpenChange={setShowAnomalyDetail}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          {anomalyDetections && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3 text-xl">
                  <Activity className="h-6 w-6 text-purple-600" />
                  Anomaly Detection Analysis
                </DialogTitle>
                <DialogDescription>
                  AI-powered behavioral analysis and threat detection
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-6 pt-4">
                {/* Summary Stats */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-purple-50 dark:bg-purple-950 rounded-lg border-2 border-purple-200 dark:border-purple-800">
                    <div className="text-4xl font-bold text-purple-600 mb-1">{anomalyDetections.total}</div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">Total Anomalies</p>
                  </div>
                  <div className="text-center p-4 bg-red-50 dark:bg-red-950 rounded-lg border-2 border-red-200 dark:border-red-800">
                    <div className="text-4xl font-bold text-red-600 mb-1">{anomalyDetections.critical}</div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">Critical Alerts</p>
                  </div>
                  <div className="text-center p-4 bg-blue-50 dark:bg-blue-950 rounded-lg border-2 border-blue-200 dark:border-blue-800">
                    <div className="text-4xl font-bold text-blue-600 mb-1">{anomalyDetections.types.length}</div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">Anomaly Types</p>
                  </div>
                </div>

                {/* Detailed Anomaly Types */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-purple-600" />
                    Detected Anomalies
                  </h3>
                  <div className="space-y-4">
                    {anomalyDetections.types.map((type, idx) => (
                      <Card key={idx} className="border-2 border-purple-200 dark:border-purple-800">
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <CardTitle className="text-lg">{type.name}</CardTitle>
                              <CardDescription>{type.description}</CardDescription>
                            </div>
                            <div className="text-right">
                              <Badge variant={type.severity === 'high' ? 'destructive' : 'secondary'} className="text-lg px-3 py-1">
                                {type.count}
                              </Badge>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">occurrences</p>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Examples:</p>
                            {type.examples && type.examples.map((example, exIdx) => (
                              <div key={exIdx} className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-900 rounded text-xs">
                                <span className="text-purple-600">•</span>
                                <span>{example}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>

                {/* ML Model Info */}
                <div className="p-4 bg-purple-50 dark:bg-purple-950 rounded-lg border border-purple-200 dark:border-purple-800">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <Activity className="h-5 w-5 text-purple-600" />
                    Machine Learning Detection
                  </h3>
                  <div className="grid md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-slate-600 dark:text-slate-400 mb-1">ML Model Version:</p>
                      <p className="font-semibold">{anomalyDetections.mlModelVersion}</p>
                    </div>
                    <div>
                      <p className="text-slate-600 dark:text-slate-400 mb-1">Last Detection:</p>
                      <p className="font-semibold">{new Date(anomalyDetections.lastDetected).toLocaleString()}</p>
                    </div>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-3">
                    Our AI-powered system uses advanced machine learning algorithms to establish baseline behavior patterns and detect deviations that may indicate security threats or policy violations.
                  </p>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Runtime Detection Detail Modal */}
      <Dialog open={showRuntimeDetail} onOpenChange={setShowRuntimeDetail}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          {runtimeThreats && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3 text-xl">
                  <PlayCircle className="h-6 w-6 text-amber-600" />
                  Runtime Threat Detection Analysis
                </DialogTitle>
                <DialogDescription>
                  Real-time monitoring and active threat prevention
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-6 pt-4">
                {/* Summary Stats */}
                <div className="grid grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-amber-50 dark:bg-amber-950 rounded-lg border-2 border-amber-200 dark:border-amber-800">
                    <div className="text-3xl font-bold text-amber-600 mb-1">{runtimeThreats.activeThreats}</div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">Active Threats</p>
                  </div>
                  <div className="text-center p-4 bg-green-50 dark:bg-green-950 rounded-lg border-2 border-green-200 dark:border-green-800">
                    <div className="text-3xl font-bold text-green-600 mb-1">{runtimeThreats.blocked}</div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">Blocked</p>
                  </div>
                  <div className="text-center p-4 bg-blue-50 dark:bg-blue-950 rounded-lg border-2 border-blue-200 dark:border-blue-800">
                    <div className="text-3xl font-bold text-blue-600 mb-1">{runtimeThreats.monitoredProcesses}</div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">Processes Monitored</p>
                  </div>
                  <div className="text-center p-4 bg-purple-50 dark:bg-purple-950 rounded-lg border-2 border-purple-200 dark:border-purple-800">
                    <div className="text-3xl font-bold text-purple-600 mb-1">{runtimeThreats.monitoredResources}</div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">Resources</p>
                  </div>
                </div>

                {/* Threat Categories */}
                <div>
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-amber-600" />
                    Runtime Threat Categories
                  </h3>
                  <div className="space-y-4">
                    {runtimeThreats.categories.map((cat, idx) => (
                      <Card key={idx} className={`border-2 ${
                        cat.risk === 'critical' ? 'border-red-200 dark:border-red-800' : 
                        cat.risk === 'high' ? 'border-orange-200 dark:border-orange-800' : 
                        'border-yellow-200 dark:border-yellow-800'
                      }`}>
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3 flex-1">
                              <AlertTriangle className={`h-6 w-6 mt-1 ${
                                cat.risk === 'critical' ? 'text-red-600' : 
                                cat.risk === 'high' ? 'text-orange-600' : 
                                'text-yellow-600'
                              }`} />
                              <div className="flex-1">
                                <CardTitle className="text-lg">{cat.name}</CardTitle>
                                <CardDescription>{cat.description}</CardDescription>
                              </div>
                            </div>
                            <div className="text-right">
                              <Badge variant={cat.risk === 'critical' ? 'destructive' : 'default'} className="text-lg px-3 py-1">
                                {cat.count}
                              </Badge>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">{cat.risk} risk</p>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Detected Threats:</p>
                            {cat.examples && cat.examples.map((example, exIdx) => (
                              <div key={exIdx} className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-900 rounded text-xs">
                                <span className={
                                  cat.risk === 'critical' ? 'text-red-600' : 
                                  cat.risk === 'high' ? 'text-orange-600' : 
                                  'text-yellow-600'
                                }>•</span>
                                <span>{example}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>

                {/* Protection Status */}
                <div className="p-4 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                  <h3 className="font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-green-600" />
                    Real-Time Protection Status
                  </h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm">Threat Blocking Effectiveness</span>
                        <span className="text-sm font-bold text-green-600">
                          {Math.round((runtimeThreats.blocked / runtimeThreats.activeThreats) * 100)}%
                        </span>
                      </div>
                      <Progress value={(runtimeThreats.blocked / runtimeThreats.activeThreats) * 100} className="h-2" />
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Runtime protection is actively monitoring {runtimeThreats.monitoredProcesses} processes across {runtimeThreats.monitoredResources} resources. 
                      Last scan completed at {new Date(runtimeThreats.lastScan).toLocaleString()}.
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Dashboard Panel */}
      {showDashboard && environment && (
        <div className="fixed top-20 right-4 w-96 max-h-[80vh] overflow-y-auto bg-white dark:bg-slate-900 rounded-lg shadow-2xl border-2 border-blue-200 dark:border-blue-700 z-50">
          <div className="p-4 border-b sticky top-0 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-bold text-lg flex items-center gap-2">
                <Info className="h-5 w-5 text-blue-600" />
                Resource Dashboard
              </h3>
              <Button variant="ghost" size="sm" onClick={() => setShowDashboard(false)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Currently selected: {selectedResources.length} resources
            </p>
          </div>

          <div className="p-4 space-y-4">
            {/* Selected Resources Summary */}
            <div className="grid grid-cols-2 gap-2">
              <div className="text-center p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
                <Server className="h-6 w-6 mx-auto mb-1 text-blue-600" />
                <div className="text-xl font-bold">
                  {environment.vms.filter(vm => selectedResources.includes(vm.id)).length}
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400">VMs Selected</div>
              </div>
              <div className="text-center p-3 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                <Database className="h-6 w-6 mx-auto mb-1 text-green-600" />
                <div className="text-xl font-bold">
                  {environment.databases.filter(db => selectedResources.includes(db.id)).length}
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400">Databases Selected</div>
              </div>
              <div className="text-center p-3 bg-purple-50 dark:bg-purple-950 rounded-lg border border-purple-200 dark:border-purple-800">
                <HardDrive className="h-6 w-6 mx-auto mb-1 text-purple-600" />
                <div className="text-xl font-bold">
                  {environment.storage.filter(s => selectedResources.includes(s.id)).length}
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400">Storage Selected</div>
              </div>
              <div className="text-center p-3 bg-orange-50 dark:bg-orange-950 rounded-lg border border-orange-200 dark:border-orange-800">
                <Users className="h-6 w-6 mx-auto mb-1 text-orange-600" />
                <div className="text-xl font-bold">
                  {environment.iam.filter(i => selectedResources.includes(i.id)).length}
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-400">IAM Selected</div>
              </div>
            </div>

            {/* Selected Resources Details */}
            <div>
              <h4 className="font-semibold text-sm mb-2">Selected Resources Details</h4>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {/* VMs */}
                {environment.vms.filter(vm => selectedResources.includes(vm.id)).map(vm => (
                  <div key={vm.id} className="p-3 border rounded-lg bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <div className="flex items-start gap-2 mb-1">
                      <Server className="h-4 w-4 text-blue-600 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{vm.name}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400">{vm.os} • {vm.instanceType}</p>
                        <Badge variant="destructive" className="text-xs mt-1">
                          {vm.vulnerabilities.length} vulnerabilities
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Databases */}
                {environment.databases.filter(db => selectedResources.includes(db.id)).map(db => (
                  <div key={db.id} className="p-3 border rounded-lg bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800">
                    <div className="flex items-start gap-2 mb-1">
                      <Database className="h-4 w-4 text-green-600 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{db.name}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400">{db.type} {db.version}</p>
                        <Badge variant="destructive" className="text-xs mt-1">
                          {db.vulnerabilities.length} vulnerabilities
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Storage */}
                {environment.storage.filter(s => selectedResources.includes(s.id)).map(bucket => (
                  <div key={bucket.id} className="p-3 border rounded-lg bg-purple-50 dark:bg-purple-950 border-purple-200 dark:border-purple-800">
                    <div className="flex items-start gap-2 mb-1">
                      <HardDrive className="h-4 w-4 text-purple-600 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{bucket.name}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400">{bucket.size} • {bucket.objects} objects</p>
                        <Badge variant="destructive" className="text-xs mt-1">
                          {bucket.vulnerabilities.length} vulnerabilities
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}

                {/* IAM */}
                {environment.iam.filter(i => selectedResources.includes(i.id)).map(role => (
                  <div key={role.id} className="p-3 border rounded-lg bg-orange-50 dark:bg-orange-950 border-orange-200 dark:border-orange-800">
                    <div className="flex items-start gap-2 mb-1">
                      <Users className="h-4 w-4 text-orange-600 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{role.name}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400">{role.users} users</p>
                        <Badge variant="destructive" className="text-xs mt-1">
                          {role.vulnerabilities.length} vulnerabilities
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Network */}
                {environment.network.filter(n => selectedResources.includes(n.id)).map(sg => (
                  <div key={sg.id} className="p-3 border rounded-lg bg-red-50 dark:bg-red-950 border-red-200 dark:border-red-800">
                    <div className="flex items-start gap-2 mb-1">
                      <Network className="h-4 w-4 text-red-600 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{sg.name}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400">{sg.rules.length} rules</p>
                        <Badge variant="destructive" className="text-xs mt-1">
                          {sg.vulnerabilities.length} vulnerabilities
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Total Vulnerabilities */}
            <div className="p-4 bg-red-50 dark:bg-red-950 rounded-lg border-2 border-red-200 dark:border-red-800">
              <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">Total Vulnerabilities in Selection</p>
              <p className="text-3xl font-bold text-red-600">
                {[...environment.vms, ...environment.databases, ...environment.storage, ...environment.iam, ...environment.network]
                  .filter(r => selectedResources.includes(r.id))
                  .reduce((sum, r) => sum + r.vulnerabilities.length, 0)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Windows Environment Modal */}
      <WindowsEnvironment 
        isOpen={showWindowsEnv} 
        onClose={() => setShowWindowsEnv(false)}
        onFileSystemChange={handleFileSystemChange}
      />
    </div>
  );
}

// Add Resource Form Component
function AddResourceForm({ resourceType, setResourceType, onSubmit, onCancel }) {
  const [formData, setFormData] = useState({
    id: `${resourceType}-${Date.now()}`,
    name: '',
    os: 'Ubuntu 22.04',
    region: 'us-east-1',
    instanceType: 't3.medium',
    type: 'PostgreSQL',
    version: '14.0',
    size: '100 GB',
    public: false,
    vulnerabilities: []
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit({ ...formData, resourceType, id: `${resourceType}-${Date.now()}` });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Resource Type Selection */}
      <div>
        <label className="text-sm font-medium mb-2 block">Resource Type</label>
        <div className="grid grid-cols-3 gap-2">
          <Button
            type="button"
            variant={resourceType === 'vm' ? 'default' : 'outline'}
            onClick={() => setResourceType('vm')}
            className="w-full"
          >
            <Server className="h-4 w-4 mr-2" />
            Virtual Machine
          </Button>
          <Button
            type="button"
            variant={resourceType === 'database' ? 'default' : 'outline'}
            onClick={() => setResourceType('database')}
            className="w-full"
          >
            <Database className="h-4 w-4 mr-2" />
            Database
          </Button>
          <Button
            type="button"
            variant={resourceType === 'storage' ? 'default' : 'outline'}
            onClick={() => setResourceType('storage')}
            className="w-full"
          >
            <HardDrive className="h-4 w-4 mr-2" />
            Storage
          </Button>
        </div>
      </div>

      {/* Common Fields */}
      <div>
        <label className="text-sm font-medium mb-2 block">Resource Name</label>
        <input
          type="text"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className="w-full px-3 py-2 border rounded-md"
          placeholder="e.g., web-server-prod"
          required
        />
      </div>

      {/* Virtual Machine Fields */}
      {resourceType === 'vm' && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Operating System</label>
              <select
                value={formData.os}
                onChange={(e) => setFormData({ ...formData, os: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="Ubuntu 22.04">Ubuntu 22.04</option>
                <option value="Ubuntu 20.04">Ubuntu 20.04</option>
                <option value="Ubuntu 18.04">Ubuntu 18.04</option>
                <option value="CentOS 7">CentOS 7</option>
                <option value="CentOS 8">CentOS 8</option>
                <option value="Debian 11">Debian 11</option>
                <option value="Debian 10">Debian 10</option>
                <option value="Red Hat Enterprise Linux 8">Red Hat Enterprise Linux 8</option>
                <option value="Amazon Linux 2">Amazon Linux 2</option>
                <option value="Windows Server 2022">Windows Server 2022</option>
                <option value="Windows Server 2019">Windows Server 2019</option>
              </select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Region</label>
              <select
                value={formData.region}
                onChange={(e) => setFormData({ ...formData, region: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-1">US West (N. California)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="eu-central-1">EU (Frankfurt)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-sm font-medium mb-2 block">Instance Type</label>
            <select
              value={formData.instanceType}
              onChange={(e) => setFormData({ ...formData, instanceType: e.target.value })}
              className="w-full px-3 py-2 border rounded-md"
            >
              <option value="t3.micro">t3.micro (1 vCPU, 1 GB RAM)</option>
              <option value="t3.small">t3.small (2 vCPU, 2 GB RAM)</option>
              <option value="t3.medium">t3.medium (2 vCPU, 4 GB RAM)</option>
              <option value="t3.large">t3.large (2 vCPU, 8 GB RAM)</option>
              <option value="t3.xlarge">t3.xlarge (4 vCPU, 16 GB RAM)</option>
              <option value="t3.2xlarge">t3.2xlarge (8 vCPU, 32 GB RAM)</option>
              <option value="m5.large">m5.large (2 vCPU, 8 GB RAM)</option>
              <option value="m5.xlarge">m5.xlarge (4 vCPU, 16 GB RAM)</option>
              <option value="c5.large">c5.large (2 vCPU, 4 GB RAM)</option>
            </select>
          </div>
        </>
      )}

      {/* Database Fields */}
      {resourceType === 'database' && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Database Type</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="PostgreSQL">PostgreSQL</option>
                <option value="MySQL">MySQL</option>
                <option value="MongoDB">MongoDB</option>
                <option value="Redis">Redis</option>
                <option value="MariaDB">MariaDB</option>
                <option value="Oracle">Oracle</option>
                <option value="SQL Server">SQL Server</option>
              </select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Version</label>
              <input
                type="text"
                value={formData.version}
                onChange={(e) => setFormData({ ...formData, version: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="e.g., 14.0"
                required
              />
            </div>
          </div>
        </>
      )}

      {/* Storage Fields */}
      {resourceType === 'storage' && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Storage Size</label>
              <input
                type="text"
                value={formData.size}
                onChange={(e) => setFormData({ ...formData, size: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="e.g., 100 GB"
                required
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.public}
                  onChange={(e) => setFormData({ ...formData, public: e.target.checked })}
                />
                Public Access
              </label>
            </div>
          </div>
        </>
      )}

      <div className="flex gap-2 justify-end pt-4">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit">
          Add Resource
        </Button>
      </div>
    </form>
  );
}

