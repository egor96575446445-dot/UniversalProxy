import os
import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from bratikvpn.core.openvpn_manager import OpenVPNManager
from bratikvpn.core.server_manager import ServerManager
from bratikvpn.gui.main_window import MainWindow


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OPENVPN = Path(r"C:\Program Files\OpenVPN\bin\openvpn.exe")


def main() -> int:
    app = QApplication(sys.argv)
    catalog = BASE_DIR / "assets" / "servers.json"
    executable = Path(os.getenv("BRATIKVPN_OPENVPN", str(DEFAULT_OPENVPN)))

    server_manager = ServerManager(catalog)
    vpn_manager = OpenVPNManager(executable)
    window = MainWindow(server_manager, vpn_manager)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
