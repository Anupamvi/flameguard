"""Split a list of NormalizedRules into overlapping chunks for LLM analysis."""

from __future__ import annotations

from dataclasses import dataclass

from app.parsers.base import NormalizedRule


@dataclass
class RuleChunk:
    """A chunk of rules to send to the LLM in a single request."""

    index: int
    total_chunks: int
    rules: list[NormalizedRule]
    is_first: bool
    is_last: bool


class RuleSetChunker:
    """Chunk rules with overlap so the LLM can detect cross-boundary issues.

    Parameters
    ----------
    max_rules_per_chunk:
        Maximum number of rules in each chunk.
    overlap:
        Number of rules from the end of one chunk repeated at the start of the
        next.  Helps the LLM spot shadowing / contradictions across boundaries.
    """

    def __init__(self, max_rules_per_chunk: int = 50, overlap: int = 5) -> None:
        self.max_rules_per_chunk = max_rules_per_chunk
        self.overlap = overlap

    def chunk(self, rules: list[NormalizedRule]) -> list[RuleChunk]:
        """Sort rules by priority and split into overlapping chunks."""
        if not rules:
            return []

        # Sort: rules with priority first (ascending), then rules without priority
        sorted_rules = sorted(
            rules,
            key=lambda r: (r.priority is None, r.priority or 0),
        )

        chunks: list[RuleChunk] = []
        step = max(self.max_rules_per_chunk - self.overlap, 1)
        total = len(sorted_rules)
        start = 0
        while start < total:
            end = min(start + self.max_rules_per_chunk, total)
            chunk_rules = sorted_rules[start:end]
            chunks.append(
                RuleChunk(
                    index=len(chunks) + 1,
                    total_chunks=0,  # filled in below
                    rules=chunk_rules,
                    is_first=(start == 0),
                    is_last=(end >= total),
                )
            )
            start += step
            # Avoid infinite loop when step == 0 should not happen but guard
            if start <= (end - self.max_rules_per_chunk):
                break

        # Fix total_chunks on every chunk
        for c in chunks:
            c.total_chunks = len(chunks)

        return chunks
