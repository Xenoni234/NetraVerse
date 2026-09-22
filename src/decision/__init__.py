"""Decision support — turn a forecast + detector verdict into an operator action.

The two-tier local-LLM advisor (Ollama) drafts and reasons about the
containment action; the human still approves and the controller executes. Falls
back to the deterministic per-stage mapping when Ollama is unavailable.
"""

from src.decision.llm_advisor import advise, ollama_available, warmup

__all__ = ["advise", "ollama_available", "warmup"]
