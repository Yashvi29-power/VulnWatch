"""
VulnWatch - Data Models & Schemas
Domain: CyberSecurity & DevOps
Continuous Vulnerability Monitoring & Runtime Behavior Analysis
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ContainerStatusEnum(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"


class EventTypeEnum(str, Enum):
    SYSCALL = "SYSCALL"
    NETWORK = "NETWORK"
    FILE_ACCESS = "FILE_ACCESS"
    PRIV_ESC = "PRIV_ESC"
    CPU_SPIKE = "CPU_SPIKE"
    LLM_PROBE = "LLM_PROBE"


# -------------------- Package & SBOM Models --------------------

class PackageItem(BaseModel):
    id: str
    name: str
    version: str
    type: str  # os-deb, os-apk, pypi, npm, go, jar
    license: Optional[str] = "MIT"
    cpe: Optional[str] = None
    path: Optional[str] = None
    vulnerabilities_count: int = 0


class SBOMReport(BaseModel):
    container_id: str
    container_name: str
    image: str
    format: str = "CycloneDX-1.5"
    extracted_at: str
    package_coverage_percentage: float = 98.4
    total_packages: int
    packages: List[PackageItem]


# -------------------- CVE & Vulnerability Models --------------------

class CVERecord(BaseModel):
    cve_id: str
    title: str
    description: str
    severity: SeverityEnum
    cvss_score: float
    epss_score: float  # Exploit Prediction Scoring System
    affected_package: str
    affected_version_range: str
    fixed_version: str
    cwe_id: str
    exploit_available: bool = False
    runtime_vector: Optional[str] = None  # e.g., "execve(/bin/sh)", "inbound_ldap", "file_read(/etc/shadow)"
    published_date: str
    remediation_advice: Optional[str] = None


class ContainerCVE(BaseModel):
    cve: CVERecord
    package: PackageItem
    is_actively_exploited_runtime: bool = False
    runtime_alert_count: int = 0


# -------------------- Approach A: Runtime Monitoring Models --------------------

class RuntimeEvent(BaseModel):
    id: str
    container_id: str
    container_name: str
    timestamp: str
    event_type: EventTypeEnum
    syscall_name: Optional[str] = None  # execve, openat, socket, connect, setuid, ptrace
    process_name: str
    pid: int
    severity: SeverityEnum
    source: str
    target: str  # e.g., "/etc/shadow", "185.220.101.5:4444", "/bin/sh"
    details: str
    correlated_cve_id: Optional[str] = None
    is_anomaly: bool = True
    mitre_attack_technique: Optional[str] = None  # e.g., "T1059 (Command Execution)"
    blocked: bool = False


# -------------------- Approach B: LLM Safety Models --------------------

class LLMProbeCategory(str, Enum):
    PROMPT_INJECTION = "Prompt Injection"
    SYSTEM_LEAKAGE = "System-Prompt Leakage"
    JAILBREAK = "Jailbreak Attempts"
    SENSITIVE_DATA = "Data Extraction & PII"
    MODEL_DOS = "Denial of Service / Loop"


class LLMTarget(BaseModel):
    id: str
    name: str
    provider: str  # Groq, Gemini, Ollama, OpenAI, Local-Mock
    model_name: str
    endpoint: str
    status: str = "ONLINE"
    total_probes_run: int = 0
    pass_rate: float = 0.0


class LLMProbeResult(BaseModel):
    id: str
    target_id: str
    probe_name: str
    category: LLMProbeCategory
    payload: str
    response_preview: str
    passed: bool
    risk_level: SeverityEnum
    confidence_score: float  # 0.0 - 1.0
    timestamp: str
    latency_ms: int
    mitigation_suggested: Optional[str] = None


# -------------------- Unified Container Model --------------------

class Container(BaseModel):
    id: str
    name: str
    image: str
    status: ContainerStatusEnum
    ip_address: str
    cpu_usage_pct: float
    memory_mb: float
    created_at: str
    packages_count: int
    cve_critical: int
    cve_high: int
    cve_medium: int
    cve_low: int
    health_score: int  # 0 - 100 (100 is pristine)
    has_active_runtime_threat: bool = False
    has_llm_service: bool = False
    ai_risk_summary: str
    tags: List[str] = []


# -------------------- AI Copilot & Remediation Models --------------------

class RemediationPlan(BaseModel):
    id: str
    container_id: str
    cve_id: Optional[str] = None
    title: str
    description: str
    root_cause_analysis: str
    mitre_technique: Optional[str] = None
    recommended_action: str
    diff_patch: str
    commands_to_execute: List[str]
    confidence_score: float
    estimated_downtime_sec: int = 0
    status: str = "PENDING"  # PENDING, APPLIED, REJECTED


class AIChatRequest(BaseModel):
    message: str
    container_id: Optional[str] = None
    context_type: Optional[str] = "general"  # general, cve, runtime, llm


class AIChatResponse(BaseModel):
    reply: str
    suggested_actions: List[str] = []
    referenced_cves: List[str] = []
    mitre_tags: List[str] = []


# -------------------- DevOps Integrations Models --------------------

class IntegrationSettings(BaseModel):
    slack_webhook_url: str = ""
    slack_channel: str = "#security-alerts"
    slack_enabled: bool = True
    github_repo: str = "yashv-org/vulnwatch-monitored-app"
    github_token_configured: bool = True
    github_auto_issue: bool = True
    min_alert_severity: SeverityEnum = SeverityEnum.HIGH


class DispatchAlertRequest(BaseModel):
    target: str  # slack, github, all
    title: str
    severity: SeverityEnum
    container_name: str
    cve_id: Optional[str] = None
    runtime_event_id: Optional[str] = None
    details: str
    remediation: Optional[str] = None
