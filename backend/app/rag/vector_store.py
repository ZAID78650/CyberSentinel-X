"""Vector store abstraction.

Two backends:
- `LocalVectorStore` (default): deterministic hashing embeddings + numpy
  cosine similarity, persisted to disk. Zero external dependencies.
- `ChromaVectorStore`: wraps chromadb when `VECTOR_DB_BACKEND=chroma`.

pgvector/FAISS can be added later by implementing the same interface.
"""
import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.core.config import get_settings

logger = logging.getLogger(__name__)

EMBED_DIM = 256


def hash_embed(text: str, dim: int = EMBED_DIM) -> np.ndarray:
    """Deterministic character n-gram hashing embedding (no external model)."""
    vec = np.zeros(dim, dtype=np.float32)
    text = text.lower()
    for n in (2, 3, 4):
        for i in range(len(text) - n + 1):
            gram = text[i : i + n]
            h = int(hashlib.md5(gram.encode("utf-8")).hexdigest()[:8], 16)
            idx = h % dim
            sign = 1.0 if (h >> 8) % 2 == 0 else -1.0
            vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


class VectorStore(ABC):
    @abstractmethod
    def add(self, key: str, text: str, metadata: Dict) -> None: ...

    @abstractmethod
    def search(self, query: str, k: int = 5) -> List[Dict]: ...

    @abstractmethod
    def count(self) -> int: ...


class LocalVectorStore(VectorStore):
    """Numpy-backed store persisted as JSON on disk."""

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(path, exist_ok=True)
        self._items: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        f = os.path.join(self.path, "vectors.json")
        if os.path.exists(f):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for key, item in data.items():
                    item["vector"] = np.array(item["vector"], dtype=np.float32)
                    self._items[key] = item
                logger.info("vector store loaded %d items from %s", len(self._items), f)
            except Exception as exc:  # pragma: no cover
                logger.warning("could not load vector store: %s", exc)

    def _save(self) -> None:
        f = os.path.join(self.path, "vectors.json")
        tmp = f + ".tmp"
        payload = {k: {**v, "vector": v["vector"].tolist()} for k, v in self._items.items()}
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, f)

    def add(self, key: str, text: str, metadata: Dict) -> None:
        self._items[key] = {"text": text, "vector": hash_embed(text), "metadata": metadata}
        self._save()

    def search(self, query: str, k: int = 5) -> List[Dict]:
        if not self._items:
            return []
        qvec = hash_embed(query)
        scored: List[Tuple[float, str]] = []
        for key, item in self._items.items():
            score = float(np.dot(qvec, item["vector"]))
            scored.append((score, key))
        scored.sort(key=lambda t: t[0], reverse=True)
        results = []
        for score, key in scored[:k]:
            item = self._items[key]
            results.append({"key": key, "text": item["text"], "score": round(score, 4), "metadata": item["metadata"]})
        return results

    def count(self) -> int:
        return len(self._items)


class ChromaVectorStore(VectorStore):
    """Chroma backend (optional dependency)."""

    def __init__(self, path: str) -> None:
        try:
            import chromadb  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("chromadb is not installed; set VECTOR_DB_BACKEND=local") from exc
        self.client = chromadb.PersistentClient(path=path)
        self.collection = self.client.get_or_create_collection("cybersentinel_kb")

    def add(self, key: str, text: str, metadata: Dict) -> None:
        self.collection.upsert(ids=[key], documents=[text], metadatas=[metadata])

    def search(self, query: str, k: int = 5) -> List[Dict]:
        res = self.collection.query(query_texts=[query], n_results=k)
        results = []
        for i, doc in enumerate(res.get("documents", [[]])[0]):
            results.append({
                "key": res["ids"][0][i],
                "text": doc,
                "score": float(res.get("distances", [[0]])[0][i]),
                "metadata": (res.get("metadatas") or [[{}]])[0][i] or {},
            })
        return results

    def count(self) -> int:
        return self.collection.count()


_store: Optional[VectorStore] = None


def get_vector_store() -> VectorStore:
    """Factory: returns the configured vector store, falling back to local."""
    global _store
    if _store is not None:
        return _store
    settings = get_settings()
    backend = settings.vector_db_backend.lower()
    if backend == "chroma":
        try:
            _store = ChromaVectorStore(settings.vector_db_path)
            logger.info("using chroma vector store")
            return _store
        except Exception as exc:
            logger.warning("chroma unavailable (%s); falling back to local vector store", exc)
    _store = LocalVectorStore(settings.vector_db_path)
    logger.info("using local numpy vector store at %s", settings.vector_db_path)
    return _store
