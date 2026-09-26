from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import json


@dataclass(frozen=True)
class Server:
    name: str
    country: str
    config: Path
    protocol: str = "OpenVPN"


class ServerManager:
    def __init__(self, catalog_path: Path):
        self.catalog_path = catalog_path
        self._servers: list[Server] = []
        self.reload()

    def reload(self) -> None:
        if not self.catalog_path.exists():
            self._servers = []
            return
        data = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self._servers = [
            Server(
                name=item["name"],
                country=item["country"],
                config=Path(item["config"]),
                protocol=item.get("protocol", "OpenVPN"),
            )
            for item in data
        ]

    def all(self) -> list[Server]:
        return list(self._servers)

    def by_name(self, name: str) -> Optional[Server]:
        return next((server for server in self._servers if server.name == name), None)
