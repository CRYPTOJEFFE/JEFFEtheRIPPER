"""Versioned, strictly validated local recovery job specifications."""

from dataclasses import asdict, dataclass, fields
import re
from typing import Optional


ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
FORMAT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")


def validate_id(value: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ValueError("Identifier must be a lowercase 32-character UUID hex string")
    return value


@dataclass(frozen=True)
class JobSpec:
    engine: str
    format: str
    input_id: str
    wordlist_id: str
    runtime_seconds: int = 30
    engine_path: Optional[str] = None
    schema_version: int = 1

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("Unsupported job schema_version; expected 1")
        if self.engine not in ("john", "hashcat"):
            raise ValueError("Engine must be john or hashcat")
        if not isinstance(self.format, str) or not FORMAT_PATTERN.fullmatch(self.format):
            raise ValueError("Invalid engine format identifier")
        if self.engine == "hashcat" and (not self.format.isascii() or not self.format.isdecimal()):
            raise ValueError("Hashcat format must be a numeric mode identifier")
        validate_id(self.input_id)
        validate_id(self.wordlist_id)
        if type(self.runtime_seconds) is not int or not 1 <= self.runtime_seconds <= 3600:
            raise ValueError("runtime_seconds must be an integer between 1 and 3600")
        if self.engine_path is not None:
            if (not isinstance(self.engine_path, str) or not self.engine_path.strip()
                    or "\x00" in self.engine_path):
                raise ValueError("engine_path must be a nonempty path without NUL bytes")

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("Job specification must be an object")
        allowed = {field.name for field in fields(cls)}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError("Unknown job specification fields: " + ", ".join(sorted(unknown)))
        try:
            return cls(**value)
        except TypeError as exc:
            raise ValueError("Missing or invalid job specification fields") from exc

    def to_dict(self):
        return asdict(self)
