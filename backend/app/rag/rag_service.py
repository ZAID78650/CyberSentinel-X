"""RAG pipeline: document -> parse -> chunk -> embed -> store -> retrieve.

Gracefully degrades: if the vector store is unavailable, retrieval returns
empty results and callers fall back to deterministic summaries.
"""
import logging
import os
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.intel import KnowledgeDocument
from app.rag.vector_store import VectorStore, get_vector_store

logger = logging.getLogger(__name__)

CHUNK_SIZE = 700
CHUNK_OVERLAP = 100

KB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "knowledge_base")


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: List[str] = []
    buffer = ""
    for para in paragraphs:
        if len(buffer) + len(para) + 2 > size and buffer:
            chunks.append(buffer.strip())
            buffer = para
        else:
            buffer = f"{buffer}\n\n{para}" if buffer else para
    if buffer.strip():
        chunks.append(buffer.strip())
    return chunks or [text]


def index_documents(db: Session, store: Optional[VectorStore] = None) -> int:
    """Index all markdown files from data/knowledge_base into the vector store."""
    store = store or get_vector_store()
    existing_count = db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0
    if existing_count > 0 and store.count() > 0:
        return existing_count

    kb_dir = os.path.abspath(KB_DIR)
    indexed = 0
    if not os.path.isdir(kb_dir):
        logger.warning("knowledge base directory not found: %s", kb_dir)
        return 0

    for fname in sorted(os.listdir(kb_dir)):
        if not fname.endswith(".md"):
            continue
        fpath = os.path.join(kb_dir, fname)
        with open(fpath, "r", encoding="utf-8") as fh:
            content = fh.read()
        title = fname[:-3].replace("_", " ").title()
        doc = db.scalar(select(KnowledgeDocument).where(KnowledgeDocument.title == title))
        if doc is None:
            chunks = chunk_text(content)
            doc = KnowledgeDocument(
                title=title,
                source="local",
                content=content,
                doc_type=_doc_type(fname),
                chunk_count=len(chunks),
                tags=_doc_tags(fname),
            )
            db.add(doc)
            for i, chunk in enumerate(chunks):
                store.add(f"{title}::{i}", chunk, {"title": title, "doc_type": doc.doc_type, "source": "local"})
            indexed += 1
    db.commit()
    logger.info("indexed %d knowledge documents (%d chunks)", indexed, store.count())
    return indexed


def _doc_type(fname: str) -> str:
    if "playbook" in fname:
        return "playbook"
    if "policy" in fname:
        return "policy"
    if "cve" in fname:
        return "cve"
    if "mitre" in fname:
        return "mitre"
    return "reference"


def _doc_tags(fname: str) -> List[str]:
    tags = []
    for kw in ("account", "brute", "malware", "exfiltration", "privilege", "mitre", "cve", "policy", "incident"):
        if kw in fname:
            tags.append(kw)
    return tags


def retrieve_context(db: Session, query: str, k: int = 4) -> List[Dict[str, Any]]:
    """Retrieve relevant knowledge chunks for a query. Returns [] on failure."""
    try:
        store = get_vector_store()
        if store.count() == 0:
            index_documents(db, store)
        results = store.search(query, k=k)
        return [
            {
                "title": r["metadata"].get("title", r["key"]),
                "text": r["text"][:1200],
                "score": r["score"],
                "source": r["metadata"].get("source", "local"),
            }
            for r in results
            if r["score"] > 0.05
        ]
    except Exception as exc:
        logger.warning("RAG retrieval degraded: %s", exc)
        return []
