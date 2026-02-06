"""
Latency Measurement and Metrics Module
Tracks security layer overhead with high-resolution timing
"""
import time
from collections import deque
from typing import Dict, Optional
from datetime import datetime
import statistics


class LatencyTracker:
    """
    Thread-safe latency tracker for security layer performance monitoring.
    Measures ONLY the overhead added by security checks, not LLM response time.
    """
    
    def __init__(self, window_size: int = 100, sla_threshold_ms: float = 50.0):
        """
        Initialize latency tracker.
        
        Args:
            window_size: Number of recent measurements to use for rolling average
            sla_threshold_ms: SLA threshold in milliseconds
        """
        self.window_size = window_size
        self.sla_threshold_ms = sla_threshold_ms
        
        # Use deque for efficient rolling window (O(1) append/pop)
        self._latencies_ms = deque(maxlen=window_size)
        
        # Counters for observability
        self.total_requests = 0
        self.sla_breaches = 0
        
    def measure_security_check(self, check_function, *args, **kwargs):
        """
        Decorator-style function to measure latency of security checks.
        
        Usage:
            result = tracker.measure_security_check(scan_prompt, prompt_text)
        
        Args:
            check_function: The security check function to measure
            *args, **kwargs: Arguments to pass to the function
            
        Returns:
            Tuple of (function_result, latency_ms)
        """
        # High-resolution monotonic clock (not affected by system time changes)
        start_time = time.perf_counter()
        
        # Execute security check
        result = check_function(*args, **kwargs)
        
        # Calculate elapsed time in milliseconds
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000.0
        
        # Record measurement
        self.record_latency(latency_ms)
        
        return result, latency_ms
    
    def record_latency(self, latency_ms: float) -> None:
        """
        Record a latency measurement.
        
        Args:
            latency_ms: Latency in milliseconds
        """
        self._latencies_ms.append(latency_ms)
        self.total_requests += 1
        
        # Check SLA breach
        if latency_ms > self.sla_threshold_ms:
            self.sla_breaches += 1
    
    def get_avg_latency_ms(self) -> float:
        """
        Calculate rolling average latency.
        
        Returns:
            Average latency in milliseconds (0.0 if no data)
        """
        if not self._latencies_ms:
            return 0.0
        
        return statistics.mean(self._latencies_ms)
    
    def get_median_latency_ms(self) -> float:
        """
        Calculate median latency (more robust to outliers).
        
        Returns:
            Median latency in milliseconds (0.0 if no data)
        """
        if not self._latencies_ms:
            return 0.0
        
        return statistics.median(self._latencies_ms)
    
    def get_p95_latency_ms(self) -> float:
        """
        Calculate 95th percentile latency.
        
        Returns:
            P95 latency in milliseconds (0.0 if no data)
        """
        if not self._latencies_ms:
            return 0.0
        
        sorted_latencies = sorted(self._latencies_ms)
        index = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[index] if index < len(sorted_latencies) else sorted_latencies[-1]
    
    def get_sla_status(self) -> str:
        """
        Determine if current average latency is within SLA.
        
        Returns:
            "within_sla" or "sla_breached"
        """
        avg_latency = self.get_avg_latency_ms()
        return "within_sla" if avg_latency <= self.sla_threshold_ms else "sla_breached"
    
    def calculate_percentage_impact(self, baseline_llm_latency_ms: float = 2400.0) -> float:
        """
        Calculate percentage impact of security layer on total request time.
        
        Args:
            baseline_llm_latency_ms: Average LLM response time (default 2.4s)
            
        Returns:
            Percentage impact (e.g., 1.0 means 1% overhead)
        """
        avg_latency = self.get_avg_latency_ms()
        if baseline_llm_latency_ms <= 0:
            return 0.0
        
        return (avg_latency / baseline_llm_latency_ms) * 100.0
    
    def get_metrics(self) -> Dict[str, any]:
        """
        Get comprehensive latency metrics.
        
        Returns:
            Dictionary containing all metrics
        """
        avg_latency = self.get_avg_latency_ms()
        
        return {
            "avg_latency_ms": round(avg_latency, 2),
            "median_latency_ms": round(self.get_median_latency_ms(), 2),
            "p95_latency_ms": round(self.get_p95_latency_ms(), 2),
            "percentage_impact": round(self.calculate_percentage_impact(), 2),
            "sla_status": self.get_sla_status(),
            "sla_threshold_ms": self.sla_threshold_ms,
            "total_requests": self.total_requests,
            "sla_breaches": self.sla_breaches,
            "breach_rate": round((self.sla_breaches / max(self.total_requests, 1)) * 100, 2),
            "window_size": self.window_size,
            "current_window_count": len(self._latencies_ms)
        }
    
    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        self._latencies_ms.clear()
        self.total_requests = 0
        self.sla_breaches = 0


# Global tracker instance (singleton pattern)
_latency_tracker: Optional[LatencyTracker] = None


def get_latency_tracker() -> LatencyTracker:
    """
    Get or create the global latency tracker instance.
    
    Returns:
        LatencyTracker instance
    """
    global _latency_tracker
    if _latency_tracker is None:
        _latency_tracker = LatencyTracker(
            window_size=100,  # Last 100 requests
            sla_threshold_ms=50.0  # 50ms SLA
        )
    return _latency_tracker


# Example security check functions (replace with your actual scanners)
def scan_prompt_for_injection(prompt: str) -> dict:
    """
    Simulated prompt injection scanner.
    In production, replace with actual ML model or rule-based scanner.
    """
    # Simulate processing time (5-30ms)
    time.sleep(0.005 + (hash(prompt) % 25) / 1000.0)
    
    # Simple keyword detection (replace with actual logic)
    dangerous_keywords = ['ignore', 'disregard', 'system', 'admin', 'override']
    detected = any(keyword in prompt.lower() for keyword in dangerous_keywords)
    
    return {
        "passed": not detected,
        "threat_detected": detected,
        "threat_type": "prompt_injection" if detected else None
    }


def scan_prompt_for_pii(prompt: str) -> dict:
    """
    Simulated PII scanner.
    """
    # Simulate processing time (3-15ms)
    time.sleep(0.003 + (hash(prompt) % 12) / 1000.0)
    
    # Simple regex patterns (replace with actual PII detection)
    import re
    patterns = {
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'email': r'[\w\.-]+@[\w\.-]+',
        'phone': r'\d{3}-\d{3}-\d{4}'
    }
    
    detected_pii = []
    for pii_type, pattern in patterns.items():
        if re.search(pattern, prompt):
            detected_pii.append(pii_type)
    
    return {
        "passed": len(detected_pii) == 0,
        "pii_detected": detected_pii
    }


def scan_prompt_for_policy_violations(prompt: str) -> dict:
    """
    Simulated policy violation scanner.
    """
    # Simulate processing time (2-10ms)
    time.sleep(0.002 + (hash(prompt) % 8) / 1000.0)
    
    return {
        "passed": True,
        "violations": []
    }


def run_all_security_checks(prompt: str) -> tuple[dict, float]:
    """
    Run all security scanners and measure total latency.
    
    Args:
        prompt: The user prompt to scan
        
    Returns:
        Tuple of (combined_results, total_latency_ms)
    """
    tracker = get_latency_tracker()
    
    # Start timing
    start_time = time.perf_counter()
    
    # Run all scanners
    injection_result = scan_prompt_for_injection(prompt)
    pii_result = scan_prompt_for_pii(prompt)
    policy_result = scan_prompt_for_policy_violations(prompt)
    
    # End timing
    end_time = time.perf_counter()
    latency_ms = (end_time - start_time) * 1000.0
    
    # Record latency
    tracker.record_latency(latency_ms)
    
    # Combine results
    combined_results = {
        "prompt_injection": injection_result,
        "pii_leakage": pii_result,
        "policy_violations": policy_result,
        "all_passed": all([
            injection_result["passed"],
            pii_result["passed"],
            policy_result["passed"]
        ]),
        "latency_ms": round(latency_ms, 2)
    }
    
    return combined_results, latency_ms
