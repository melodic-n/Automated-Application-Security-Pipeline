from dataclasses import dataclass, asdict, field
  
@dataclass
class Finding:
    """Normalized finding schema shared across all tools."""
    id: str
    tool: str
    category: str          # "sast" | "secret" | "dependency"
    severity: str           # "critical" | "high" | "medium" | "low" | "info"
    title: str
    description: str
    file: str
    line: int | None
    raw: dict = field(default_factory=dict)
 
 