"""
Security Metrics API Endpoints
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, List, Any
from security_metrics_db import (
    get_security_metrics_summary,
    record_threat_detection,
    reset_metrics,
    increment_total_requests
)

router = APIRouter(prefix="/api/security", tags=["security"])


class ThreatDetectionRequest(BaseModel):
    """Request model for recording threat detection"""
    threat_type: str
    severity: str = "medium"
    blocked: bool = True


class SecurityMetricsResponse(BaseModel):
    """Response model for security metrics"""
    total_requests: int
    threats_blocked: int
    threats_flagged: int
    block_rate: float
    top_threat_vector: Dict[str, Any]
    all_threat_vectors: List[Dict[str, Any]]
    last_updated: str = None


@router.get("/metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics():
    """
    Get comprehensive security metrics from database.
    
    Returns:
        - total_requests: Total number of requests processed
        - threats_blocked: Total number of threats blocked
        - threats_flagged: Total number of threats flagged
        - block_rate: Percentage of requests that were threats
        - top_threat_vector: Most common threat type
        - all_threat_vectors: All threat types ranked by frequency
    
    Example response:
    ```json
    {
      "total_requests": 1247,
      "threats_blocked": 342,
      "threats_flagged": 28,
      "block_rate": 27.42,
      "top_threat_vector": {
        "name": "DAN Attacks",
        "count": 128,
        "severity": "critical"
      },
      "all_threat_vectors": [
        {"threat_type": "DAN Attacks", "count": 128, "severity": "critical"},
        {"threat_type": "Jailbreak", "count": 95, "severity": "high"}
      ]
    }
    ```
    """
    metrics = get_security_metrics_summary()
    
    return SecurityMetricsResponse(
        total_requests=metrics["total_requests"],
        threats_blocked=metrics["threats_blocked"],
        threats_flagged=metrics["threats_flagged"],
        block_rate=metrics["block_rate"],
        top_threat_vector=metrics["top_threat_vector"],
        all_threat_vectors=metrics["all_threat_vectors"],
        last_updated=metrics["last_updated"]
    )


@router.post("/record-threat")
async def record_threat(request: ThreatDetectionRequest):
    """
    Record a threat detection event.
    
    This endpoint is called when a threat is detected to:
    - Increment total requests counter
    - Increment threats blocked counter (if blocked=true)
    - Update threat vector statistics
    
    Args:
        threat_type: Type of threat (e.g., "DAN Attacks", "Jailbreak")
        severity: Severity level (low, medium, high, critical)
        blocked: Whether the threat was blocked
    
    Example request:
    ```json
    {
      "threat_type": "DAN Attacks",
      "severity": "critical",
      "blocked": true
    }
    ```
    """
    record_threat_detection(
        threat_type=request.threat_type,
        severity=request.severity,
        blocked=request.blocked
    )
    
    return {
        "status": "success",
        "message": f"Threat recorded: {request.threat_type}",
        "metrics": get_security_metrics_summary()
    }


@router.post("/record-request")
async def record_clean_request():
    """
    Record a clean request (no threats detected).
    
    Increments the total requests counter without incrementing threats blocked.
    """
    increment_total_requests()
    
    return {
        "status": "success",
        "message": "Clean request recorded"
    }


@router.post("/reset")
async def reset_all_metrics():
    """
    Reset all security metrics to zero.
    
    ⚠️ WARNING: This clears all data!
    In production, this should be protected by authentication.
    """
    reset_metrics()
    
    return {
        "status": "success",
        "message": "All security metrics have been reset",
        "metrics": get_security_metrics_summary()
    }


@router.get("/health")
async def security_metrics_health():
    """Health check for security metrics system"""
    metrics = get_security_metrics_summary()
    
    return {
        "status": "healthy",
        "total_requests": metrics["total_requests"],
        "database": "connected"
    }
