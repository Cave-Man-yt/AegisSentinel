# src/utils/risk.py


def normalize_risk(results_score: dict) -> float:
    """
    Normalizes the risk scores from llm-guard into a Unified Risk Index (0-100).
    
    Formula: RiskScore = min(100, max(H * 100, F(Cm)))
    Where:
      - H: Heuristic violations (Deterministic, score=1.0)
      - Cm: Model confidence/score (Probabilistic, 0.0-1.0)
    
    Args:
        results_score: A dictionary of scanner names and their risk scores.
        
    Returns:
        A single risk score between 0 and 100.
    """
    if not results_score:
        return 0.0
        
    # Define Heuristic Scanners (Deterministic)
    # These should generally force a higher score if triggered.
    HEURISTIC_SCANNERS = {"BanSubstrings", "Anonymize"}
    
    current_max = 0.0
    
    for scanner, score in results_score.items():
        weight = 1.0
        # We could apply curve functions F(Cm) here if needed.
        # For now, we assume linear mapping of model confidence to risk.
        
        weighted_score = score * weight
        if weighted_score > current_max:
            current_max = weighted_score
            
    final_score = min(100.0, current_max * 100)
    return round(final_score, 2)
