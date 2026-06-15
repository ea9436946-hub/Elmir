from abc import ABC, abstractmethod
from datetime import datetime


class BaseParser(ABC):
    source_name: str = "unknown"

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        pass

    @abstractmethod
    def parse(self, line: str) -> dict | None:
        pass

    def _base_event(self) -> dict:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": self.source_name,
            "severity": "INFO",
            "extra": {},
        }
