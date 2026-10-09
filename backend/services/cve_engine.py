"""
VulnWatch - CVE & NVD Matching Engine
Correlates packages & CPEs with National Vulnerability Database & OSV
"""

import httpx
from typing import List, Dict, Optional, Any
from models import CVERecord, SeverityEnum, PackageItem
from database import db


class CVEEngineService:
    @staticmethod
    def match_package_cves(package_name: str, version: str) -> List[CVERecord]:
        """Match a given package against our CVE database"""
        matched = []
        pkg_lower = package_name.lower()
        for cve in db.cve_database.values():
            if cve.affected_package.lower() in pkg_lower or pkg_lower in cve.affected_package.lower():
                matched.append(cve)
        return matched

    @staticmethod
    def get_container_cves(container_id: str) -> List[Dict[str, Any]]:
        """Get all correlated CVEs for a specific container's packages"""
        sbom = db.sboms.get(container_id)
        if not sbom:
            return []

        results = []
        for pkg in sbom.packages:
            cves = CVEEngineService.match_package_cves(pkg.name, pkg.version)
            for cve in cves:
                # Check if there is active runtime behavior for this CVE
                active_events = [
                    e for e in db.runtime_events 
                    if e.container_id == container_id and e.correlated_cve_id == cve.cve_id
                ]
                results.append({
                    "package": pkg.dict(),
                    "cve": cve.dict(),
                    "is_actively_exploited_runtime": len(active_events) > 0,
                    "runtime_alert_count": len(active_events),
                    "active_events": [e.dict() for e in active_events]
                })
        return results

    @staticmethod
    async def query_nvd_online(keyword: str) -> List[Dict[str, Any]]:
        """Query public NVD REST API with fallback to local cached database"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    out = []
                    for item in vulnerabilities:
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id", "N/A")
                        descriptions = cve_data.get("descriptions", [{}])
                        desc = descriptions[0].get("value", "") if descriptions else ""
                        metrics = cve_data.get("metrics", {})
                        cvss_score = 7.5
                        severity = "HIGH"
                        
                        if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                            cvss_info = metrics["cvssMetricV31"][0].get("cvssData", {})
                            cvss_score = cvss_info.get("baseScore", 7.5)
                            severity = cvss_info.get("baseSeverity", "HIGH")
                        
                        out.append({
                            "cve_id": cve_id,
                            "description": desc,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "source": "NIST NVD Live API"
                        })
                    if out:
                        return out
        except Exception:
            pass  # Fallback to rich local database

        # Fallback to local DB filter
        results = []
        kw = keyword.lower()
        for cve in db.cve_database.values():
            if kw in cve.cve_id.lower() or kw in cve.title.lower() or kw in cve.description.lower() or kw in cve.affected_package.lower():
                results.append({
                    "cve_id": cve.cve_id,
                    "title": cve.title,
                    "description": cve.description,
                    "cvss_score": cve.cvss_score,
                    "severity": cve.severity.value,
                    "epss_score": cve.epss_score,
                    "affected_package": cve.affected_package,
                    "fixed_version": cve.fixed_version,
                    "source": "VulnWatch NVD Mirror & OSV Feed"
                })
        return results
