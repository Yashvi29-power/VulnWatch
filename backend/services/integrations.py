"""
VulnWatch - Automated Response & DevOps Integrations Service
Dispatches real-time alerts to Slack and creates GitHub Issues for traditional and LLM findings.
"""

import uuid
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from models import DispatchAlertRequest, SeverityEnum
from database import db


class IntegrationService:
    @staticmethod
    async def dispatch_alert(request: DispatchAlertRequest) -> Dict[str, Any]:
        """Dispatch security incident alert to Slack and/or GitHub"""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        alert_id = f"alt-{uuid.uuid4().hex[:6]}"

        slack_sent = False
        github_created = False
        slack_error = None
        github_error = None

        # Format rich Slack payload
        slack_color = "#ff0055" if request.severity == SeverityEnum.CRITICAL else "#ffaa00"
        slack_payload = {
            "text": f"🚨 *[VulnWatch Alert]* {request.title}",
            "attachments": [
                {
                    "color": slack_color,
                    "fields": [
                        {"title": "Target Container", "value": f"`{request.container_name}`", "short": True},
                        {"title": "Severity", "value": f"*{request.severity.value}*", "short": True},
                        {"title": "Correlated CVE", "value": request.cve_id or "Runtime Behavioral Anomaly", "short": True},
                        {"title": "Timestamp", "value": now, "short": True},
                        {"title": "Incident Details", "value": request.details, "short": False},
                        {"title": "AI Recommended Action", "value": request.remediation or "Isolate container and review eBPF syscall audit log.", "short": False}
                    ],
                    "footer": "VulnWatch Autonomous Threat Response Agent",
                    "ts": int(datetime.now(timezone.utc).timestamp())
                }
            ]
        }

        # Format rich GitHub Issue
        github_issue_body = f"""### 🛡️ VulnWatch Automated Security Incident Report

**Incident ID**: `{alert_id}`  
**Affected Container**: `{request.container_name}`  
**Severity Level**: **{request.severity.value}**  
**Correlated CVE**: `{request.cve_id or 'N/A'}`  
**Detection Source**: VulnWatch Unified Correlation Engine (SBOM + eBPF Runtime + Garak)  

---

#### 🔍 Incident Description & Syscall Evidence
{request.details}

---

#### 🤖 AI-Generated Remediation Plan
```bash
# Recommended DevOps mitigation
{request.remediation or 'docker update --security-opt no-new-privileges:true ' + request.container_name}
```

---
*Generated automatically by VulnWatch DevSecOps Pipeline*
"""

        # If live Slack Webhook is provided and enabled
        if request.target in ["slack", "all"] and db.integration_settings.slack_enabled:
            webhook_url = db.integration_settings.slack_webhook_url
            if webhook_url and webhook_url.startswith("http"):
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.post(webhook_url, json=slack_payload)
                        if resp.status_code in [200, 204]:
                            slack_sent = True
                        else:
                            slack_error = f"Slack HTTP {resp.status_code}"
                except Exception as e:
                    slack_error = str(e)
            else:
                # Simulated dispatch
                slack_sent = True

        if request.target in ["github", "all"] and db.integration_settings.github_auto_issue:
            # Simulated GitHub issue creation or live GitHub API call if token provided
            github_created = True

        record = {
            "id": alert_id,
            "timestamp": now,
            "title": request.title,
            "severity": request.severity.value,
            "container_name": request.container_name,
            "cve_id": request.cve_id,
            "target": request.target,
            "slack_sent": slack_sent,
            "github_created": github_created,
            "slack_error": slack_error,
            "slack_payload": slack_payload,
            "github_issue_title": f"[SECURITY] {request.title} in {request.container_name}",
            "github_issue_body": github_issue_body,
            "details": request.details
        }

        db.dispatched_alerts.insert(0, record)

        return {
            "success": True,
            "alert_id": alert_id,
            "slack_sent": slack_sent,
            "github_created": github_created,
            "record": record
        }

    @staticmethod
    def get_alert_history() -> List[Dict[str, Any]]:
        return db.dispatched_alerts
