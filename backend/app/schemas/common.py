"""Common response schemas."""
from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Message(BaseModel):
    message: str


class Paginated(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int


class StatusResponse(BaseModel):
    status: str
    detail: Optional[str] = None
