"""
src/rag/retriever.py
Architecture ref: docs/architecture.md § RAG-Grounded Decision Support (new — see § 4.8)

Retrieval half of the RAG pipeline. Uses BM25 (rank_bm25), a pure-Python,
pip-installable lexical ranking algorithm — deliberately chosen over neural
sentence embeddings, which would require downloading a pretrained model from
a hub and therefore break the spec's "fully offline, no cloud API
dependency, zero outbound network calls" requirement for the core system.

BM25 is not a compromise pick for this corpus: MITRE ATT&CK text is
technical and keyword-dense (specific technique names, ports, protocol
names), which is exactly the regime where lexical ranking is competitive
with — and cheaper and more auditable than — dense embeddings. See
docs/architecture.md "RAG design decisions" for the full justification and
the swap-in path to embeddings for teams with internet access.
"""
from __future__ import annotations

import re

from rank_bm25 import BM25Okapi

from src.rag.knowledge_base import KBEntry, KnowledgeBase

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class AttckRetriever:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self._corpus_tokens = [_tokenize(doc) for doc in kb.documents()]
        self._bm25 = BM25Okapi(self._corpus_tokens)

    def retrieve(self, query: str, top_k: int = 4) -> list[tuple[KBEntry, float]]:
        """Returns the top_k (entry, score) pairs ranked by BM25 relevance to
        `query`. `query` is typically built by the caller from structured
        evidence (predicted stage name + top SHAP features + top attended
        time window) rather than free text — see copilot.py build_query()."""
        scores = self._bm25.get_scores(_tokenize(query))
        ranked_idx = sorted(range(len(scores)), key=lambda i: -scores[i])[:top_k]
        return [(self.kb.entries[i], float(scores[i])) for i in ranked_idx]

    def retrieve_for_stage(self, project_stage: str, query: str, top_k: int = 4) -> list[tuple[KBEntry, float]]:
        """Constrained retrieval: only rank entries already tagged with the
        predicted kill-chain stage, then break ties with BM25 relevance to the
        specific evidence. This keeps retrieval grounded in the deterministic
        stage-mapping result from attck_mapper.py rather than letting free-text
        similarity alone pick an unrelated technique."""
        candidates = [(i, e) for i, e in enumerate(self.kb.entries) if e.project_stage == project_stage]
        if not candidates:
            return self.retrieve(query, top_k)
        q_tokens = _tokenize(query)
        scored = []
        for i, e in candidates:
            score = self._bm25.get_scores(q_tokens)[i]
            scored.append((e, float(score)))
        scored.sort(key=lambda pair: -pair[1])
        return scored[:top_k]
