"""
FastAPI Metrics Endpoints
Exposes latency and performance metrics
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from latency_tracker import get_latency_tracker, run_all_security_checks

# Create router for metrics endpoints
router = APIRouter(prefix="/metrics", tags=["metrics"])


class LatencyMetrics(BaseModel):
    """Latency metrics response model"""
    avg_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    percentage_impact: float
    sla_status: str
    sla_threshold_ms: float
    total_requests: int
    sla_breaches: int
    breach_rate: float


class SecurityCheckRequest(BaseModel):
    """Request model for security check"""
    prompt: str


class SecurityCheckResponse(BaseModel):
    """Response model for security check"""
    all_passed: bool
    latency_ms: float
    prompt_injection: Dict[str, Any]
    pii_leakage: Dict[str, Any]
    policy_violations: Dict[str, Any]


@router.get("/latency", response_model=LatencyMetrics)
async def get_latency_metrics():
    """
    Get current latency metrics for the security layer.
    
    Returns comprehensive latency statistics including:
    - Average latency (rolling window)
    - Median latency
    - 95th percentile latency
    - Percentage impact on total request time
    - SLA status
    - Breach statistics
    
    Example response:
    ```json
    {
      "avg_latency_ms": 24.5,
      "median_latency_ms": 23.1,
      "p95_latency_ms": 35.2,
      "percentage_impact": 1.02,
      "sla_status": "within_sla",
      "sla_threshold_ms": 50.0,
      "total_requests": 1247,
      "sla_breaches": 12,
      "breach_rate": 0.96
    }
    ```
    """
    tracker = get_latency_tracker()
    metrics = tracker.get_metrics()
    
    return LatencyMetrics(
        avg_latency_ms=metrics["avg_latency_ms"],
        median_latency_ms=metrics["median_latency_ms"],
        p95_latency_ms=metrics["p95_latency_ms"],
        percentage_impact=metrics["percentage_impact"],
        sla_status=metrics["sla_status"],
        sla_threshold_ms=metrics["sla_threshold_ms"],
        total_requests=metrics["total_requests"],
        sla_breaches=metrics["sla_breaches"],
        breach_rate=metrics["breach_rate"]
    )


@router.post("/scan", response_model=SecurityCheckResponse)
async def scan_prompt(request: SecurityCheckRequest):
    """
    Scan a prompt through all security checks and measure latency.
    
    This endpoint demonstrates the security layer in action:
    1. Measures start time
    2. Runs all security scanners
    3. Measures end time
    4. Records latency
    5. Returns results
    
    Args:
        request: SecurityCheckRequest with prompt text
        
    Returns:
        SecurityCheckResponse with scan results and latency
        
    Example request:
    ```json
    {
      "prompt": "Tell me about the weather"
    }
    ```
    
    Example response:
    ```json
    {
      "all_passed": true,
      "latency_ms": 18.5,
      "prompt_injection": {"passed": true, "threat_detected": false},
      "pii_leakage": {"passed": true, "pii_detected": []},
      "policy_violations": {"passed": true, "violations": []}
    }
    ```
    """
    if not request.prompt or len(request.prompt.strip()) == 0:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    # Run security checks and measure latency
    results, latency_ms = run_all_security_checks(request.prompt)
    
    return SecurityCheckResponse(
        all_passed=results["all_passed"],
        latency_ms=results["latency_ms"],
        prompt_injection=results["prompt_injection"],
        pii_leakage=results["pii_leakage"],
        policy_violations=results["policy_violations"]
    )


@router.get("/health")
async def metrics_health():
    """
    Health check for metrics system.
    
    Returns:
        Status information about the latency tracker
    """
    tracker = get_latency_tracker()
    
    return {
        "status": "healthy",
        "tracker_initialized": tracker is not None,
        "total_requests_tracked": tracker.total_requests,
        "window_size": tracker.window_size,
        "current_data_points": len(tracker._latencies_ms)
    }


@router.post("/reset")
async def reset_metrics():
    """
    Reset all metrics (admin/testing use only).
    
    ⚠️ WARNING: This clears all latency data!
    In production, this should be protected by authentication.
    """
    tracker = get_latency_tracker()
    tracker.reset()
    
    return {
        "status": "success",
        "message": "All metrics have been reset"
    }
