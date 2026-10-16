"""
VulnWatch Backend Server - FastAPI
Continuous Vulnerability Monitoring & Runtime Behavior Analysis for Containerized Applications
Domain: CyberSecurity & DevOps
"""

import os
import logging
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Load .env before anything else (GEMINI_API_KEY, ALLOWED_ORIGINS, etc.)
load_dotenv()

# Structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vulnwatch")

from models import (
    Container, ContainerStatusEnum, SBOMReport, CVERecord,
    RuntimeEvent, LLMTarget, LLMProbeResult, RemediationPlan,
    AIChatRequest, AIChatResponse, IntegrationSettings, DispatchAlertRequest
)
from database import db
from services.sbom_scanner import SBOMScannerService
from services.cve_engine import CVEEngineService
from services.runtime_agent import RuntimeAgentService
from services.runtime_scanner import DynamicRuntimeScannerService
from services.llm_scanner import LLMScannerService
from services.correlation_engine import CorrelationEngineService
from services.ai_copilot import AICopilotService
from services.integrations import IntegrationService
from services.docker_service import DockerIntegrationService


app = FastAPI(
    title="VulnWatch API",
    description="Continuous Vulnerability Monitoring & Runtime Behavior Analysis Engine",
    version="1.0.0"
)

# CORS — allow configuring origins via env var for production deployments
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    logger.info("VulnWatch backend starting — CORS origins: %s", ALLOWED_ORIGINS)
    logger.info("Gemini AI key configured: %s", bool(os.getenv('GEMINI_API_KEY')))
    logger.info("Database seeded: %d containers, %d CVEs, %d probes",
                len(db.containers), len(db.cve_database), len(db.llm_probe_results))


@app.on_event("shutdown")
async def on_shutdown():
    logger.info("VulnWatch backend shutting down.")


@app.get("/")
def root():
    return {
        "project": "VulnWatch",
        "description": "Continuous Vulnerability Monitoring & Runtime Behavior Analysis for Containerized Applications",
        "status": "OPERATIONAL",
        "team": ["24DCS136_Yashvi Thakkar", "24DCS076_Mantra Patel", "24DCS089_Tirth Patel", "24DCS098_Mitesh Patil"],
        "docs_url": "/docs"
    }


@app.get("/api/health")
def health():
    """Enhanced health check with live data store stats"""
    return {
        "status": "healthy",
        "service": "vulnwatch-backend",
        "engine_version": "1.0.0",
        "ai_copilot": "gemini-live" if os.getenv("GEMINI_API_KEY") else "built-in-heuristic",
        "data_store": {
            "containers": len(db.containers),
            "cve_records": len(db.cve_database),
            "runtime_events": len(db.runtime_events),
            "llm_probes": len(db.llm_probe_results),
            "remediation_plans": len(db.remediations),
        }
    }


# ---------------- 1. Overview & Unified Correlation ----------------

@app.get("/api/overview")
def get_cluster_overview():
    """Unified correlation posture combining SBOM, Runtime Syscalls, and LLM Probes"""
    return CorrelationEngineService.get_unified_posture()


# ---------------- 2. Container Management ----------------

@app.get("/api/containers")
def list_containers():
    """List all monitored container workloads"""
    return list(db.containers.values())


@app.get("/api/containers/{container_id}")
def get_container(container_id: str):
    container = db.containers.get(container_id)
    if not container:
        raise HTTPException(status_code=404, detail="Container not found")
    return container


@app.post("/api/containers/{container_id}/isolate")
def isolate_container(container_id: str):
    """DevOps Action: Quarantine container from network mesh"""
    try:
        return RuntimeAgentService.isolate_container(container_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/containers/{container_id}/restore")
def restore_container(container_id: str):
    """DevOps Action: Restore healthy state to container"""
    try:
        return RuntimeAgentService.restore_container(container_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/containers/register")
def register_container(name: str, image: str):
    """Register and automatically extract SBOM for a new container image"""
    cid = f"cnt-{name.lower().replace(' ', '-')}"
    new_cnt = Container(
        id=cid,
        name=name,
        image=image,
        status=ContainerStatusEnum.RUNNING,
        ip_address=f"10.244.{len(db.containers) + 1}.15",
        cpu_usage_pct=15.0,
        memory_mb=450.0,
        created_at="Just now",
        packages_count=32,
        cve_critical=0,
        cve_high=1,
        cve_medium=2,
        cve_low=1,
        health_score=88,
        has_active_runtime_threat=False,
        has_llm_service="llm" in image.lower() or "ai" in image.lower(),
        ai_risk_summary="Container registered. SBOM extracted and baseline behavioral monitor attached.",
        tags=["Dynamic-Registered", "DevOps"]
    )
    db.containers[cid] = new_cnt
    # Generate and store SBOM
    sbom = SBOMScannerService.generate_sbom_for_image(cid, name, image)
    db.sboms[cid] = sbom
    new_cnt.packages_count = len(sbom.packages)
    return {"success": True, "container": new_cnt, "sbom": sbom}


@app.post("/api/containers/upload-manifest")
async def upload_manifest(
    file: UploadFile = File(...),
    container_name: Optional[str] = Form(None),
    image_name: Optional[str] = Form(None)
):
    """
    Upload real Dockerfile, requirements.txt, package.json, or SBOM JSON for dynamic scanning.
    Parses real packages, queries NVD CVEs, and registers workload in VulnWatch.
    """
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8", errors="replace")
        target_name = container_name.strip() if container_name and container_name.strip() else file.filename.split(".")[0]
        target_img = image_name.strip() if image_name and image_name.strip() else f"manifest:{file.filename}"

        result = DockerIntegrationService.process_and_register_manifest(
            container_name=target_name,
            image_name=target_img,
            filename=file.filename,
            content=content_str
        )
        return result
    except Exception as e:
        logger.error("Failed to process uploaded manifest: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to scan manifest: {str(e)}")


# ---------------- 2b. Docker Daemon Live Inspection ----------------

@app.get("/api/docker/daemon-status")
def get_docker_daemon_status():
    """Get status of local Docker daemon (connected / disconnected)"""
    return DockerIntegrationService.get_daemon_status()


@app.get("/api/docker/local-containers")
def list_docker_local_containers():
    """List containers currently running or stopped in local Docker Desktop"""
    return DockerIntegrationService.list_local_containers()


@app.get("/api/docker/local-images")
def list_docker_local_images():
    """List local Docker images stored on machine"""
    return DockerIntegrationService.list_local_images()


# ---------------- 3. Package Inventory & SBOM ----------------

@app.get("/api/containers/{container_id}/sbom")
def get_container_sbom(container_id: str):
    """Retrieve Software Bill of Materials (SBOM) with >=95% package coverage"""
    sbom = db.sboms.get(container_id)
    if not sbom:
        cnt = db.containers.get(container_id)
        if not cnt:
            raise HTTPException(status_code=404, detail="Container not found")
        sbom = SBOMScannerService.generate_sbom_for_image(container_id, cnt.name, cnt.image)
        db.sboms[container_id] = sbom
    return sbom


@app.get("/api/containers/{container_id}/sbom/cyclonedx")
def download_cyclonedx(container_id: str):
    """Export standard CycloneDX 1.5 JSON SBOM"""
    sbom = db.sboms.get(container_id)
    if not sbom:
        cnt = db.containers.get(container_id)
        if not cnt:
            raise HTTPException(status_code=404, detail="Container not found")
        sbom = SBOMScannerService.generate_sbom_for_image(container_id, cnt.name, cnt.image)
        db.sboms[container_id] = sbom
    return SBOMScannerService.export_cyclonedx(sbom)


@app.get("/api/containers/{container_id}/sbom/spdx")
def download_spdx(container_id: str):
    """Export standard SPDX 2.3 JSON SBOM"""
    sbom = db.sboms.get(container_id)
    if not sbom:
        cnt = db.containers.get(container_id)
        if not cnt:
            raise HTTPException(status_code=404, detail="Container not found")
        sbom = SBOMScannerService.generate_sbom_for_image(container_id, cnt.name, cnt.image)
        db.sboms[container_id] = sbom
    return SBOMScannerService.export_spdx(sbom)


# ---------------- 4. CVE Feed & Matching Engine ----------------

@app.get("/api/containers/{container_id}/cves")
def get_container_cves(container_id: str):
    """Correlate container packages with CVE database"""
    return CVEEngineService.get_container_cves(container_id)


@app.get("/api/cve/all")
def get_all_cves():
    """Get all CVE records in local database"""
    return list(db.cve_database.values())


@app.get("/api/cve/search")
async def search_cves(query: str = Query(..., min_length=1)):
    """Search CVEs via NVD feed / local database"""
    return await CVEEngineService.query_nvd_online(query)


# ---------------- 5. Approach A: Dynamic Runtime Vulnerability Scanner & Syscall Monitor ----------------

@app.get("/api/runtime/events")
def get_runtime_events(container_id: Optional[str] = None, limit: int = 50):
    """Fetch live syscalls, network sockets, and file access events"""
    if container_id:
        return RuntimeAgentService.get_events_for_container(container_id)
    return RuntimeAgentService.get_all_recent_events(limit)


@app.post("/api/runtime/simulate-attack")
def simulate_runtime_attack(container_id: str, attack_type: str):
    """Simulate dynamic runtime exploitation (Log4Shell, Reverse Shell, Shadow Read, Priv Esc, Crypto Miner)"""
    try:
        event = RuntimeAgentService.simulate_attack_scenario(container_id, attack_type)
        return {"success": True, "simulated_event": event}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/runtime/scan/{container_id}")
def scan_container_runtime(container_id: str):
    """Dynamically scan container for active runtime vulnerabilities (processes, sockets, syscalls, CVEs)"""
    try:
        return DynamicRuntimeScannerService.scan_container_runtime(container_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/runtime/scan-all")
def scan_all_workloads_runtime():
    """Dynamically scan all cluster workloads for active runtime vulnerabilities"""
    return DynamicRuntimeScannerService.scan_all_containers()


@app.post("/api/runtime/kill-pid/{container_id}/{pid}")
def kill_process_pid(container_id: str, pid: int):
    """DevOps Mitigation: Terminate rogue process PID inside container"""
    try:
        return DynamicRuntimeScannerService.kill_process_pid(container_id, pid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/runtime/block-socket/{container_id}")
def block_egress_socket(container_id: str, remote_ip: str = Query(...)):
    """DevOps Mitigation: Block malicious C2 egress IP via eBPF TC filter"""
    try:
        return DynamicRuntimeScannerService.block_network_socket(container_id, remote_ip)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))



# ---------------- 6. Approach B: Dynamic LLM Vulnerability Scanning (Garak) ----------------

@app.get("/api/llm/targets")
def get_llm_targets():
    """List target LLM endpoints (Groq, Gemini, Ollama, OpenAI)"""
    return LLMScannerService.get_all_targets()


@app.get("/api/llm/probes")
def get_llm_probe_history(target_id: Optional[str] = None):
    """Get history of adversarial probe runs and pass/fail scores"""
    return LLMScannerService.get_probe_history(target_id)


class LLMProbeRequest(BaseModel):
    target_id: str
    probe_name: Optional[str] = None
    custom_payload: Optional[str] = None

@app.post("/api/llm/run-probe")
def run_llm_probe(request: LLMProbeRequest):
    """Execute dynamic Garak adversarial probe (Prompt injection, jailbreak, leakage)"""
    try:
        result = LLMScannerService.run_dynamic_probe(
            request.target_id, request.probe_name, request.custom_payload
        )
        logger.info("Garak probe executed: %s on target %s — passed=%s",
                    result.probe_name, request.target_id, result.passed)
        return {"success": True, "probe_result": result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/llm/run-suite")
def run_llm_suite(target_id: str):
    """Run full Garak adversarial probe suite against target LLM"""
    try:
        return LLMScannerService.run_full_probe_suite(target_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------- 7. AI Security Copilot & Remediation ----------------

@app.post("/api/ai/chat", response_model=AIChatResponse)
async def ai_chat(request: AIChatRequest):
    """Chat with VulnWatch AI Copilot for root-cause analysis & triage"""
    return await AICopilotService.chat(request)


@app.post("/api/ai/remediation/generate")
def generate_remediation(container_id: str, cve_id: Optional[str] = None):
    """AI generates automated Dockerfile & dependency remediation diff patch"""
    try:
        plan = AICopilotService.generate_remediation_plan(container_id, cve_id)
        return {"success": True, "remediation_plan": plan}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/remediations")
def list_remediations():
    return list(db.remediations.values())


@app.post("/api/ai/remediation/{plan_id}/apply")
def apply_remediation(plan_id: str):
    """Apply automated AI patch and restore container posture"""
    try:
        return AICopilotService.apply_remediation_plan(plan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------- 8. DevOps Integrations (Slack & GitHub) ----------------

@app.get("/api/integrations/settings")
def get_integration_settings():
    return db.integration_settings


@app.post("/api/integrations/settings")
def update_integration_settings(settings: IntegrationSettings):
    db.integration_settings = settings
    return {"success": True, "settings": db.integration_settings}


@app.post("/api/integrations/dispatch")
async def dispatch_alert(request: DispatchAlertRequest):
    """Dispatch security incident alert to Slack / GitHub"""
    return await IntegrationService.dispatch_alert(request)


@app.get("/api/integrations/alerts")
def get_alert_history():
    return IntegrationService.get_alert_history()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
