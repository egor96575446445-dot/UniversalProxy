from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QPlainTextEdit
from bratikvpn.core.openvpn_manager import VPNState


class MainWindow(QMainWindow):
    def __init__(self, server_manager, vpn_manager):
        super().__init__()
        self.server_manager = server_manager
        self.vpn_manager = vpn_manager
        self.setWindowTitle("BratikVPN")
        self.resize(760, 520)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        self.status = QLabel("Статус: отключён")
        self.servers = QComboBox()
        for server in server_manager.all():
            self.servers.addItem(f"{server.country} — {server.name}", server)

        buttons = QHBoxLayout()
        self.connect_button = QPushButton("Подключиться")
        self.disconnect_button = QPushButton("Отключиться")
        self.disconnect_button.setEnabled(False)
        buttons.addWidget(self.connect_button)
        buttons.addWidget(self.disconnect_button)

        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        layout.addWidget(QLabel("Сервер OpenVPN:"))
        layout.addWidget(self.servers)
        layout.addWidget(self.status)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Журнал:"))
        layout.addWidget(self.logs)

        self.connect_button.clicked.connect(self._connect)
        self.disconnect_button.clicked.connect(self.vpn_manager.disconnect)
        self.vpn_manager.state_changed.connect(self._on_state_changed)
        self.vpn_manager.log_line.connect(self.logs.appendPlainText)

    def _connect(self):
        server = self.servers.currentData()
        if server is not None:
            self.vpn_manager.connect_vpn(server.config)

    def _on_state_changed(self, state: VPNState):
        labels = {
            VPNState.DISCONNECTED: "Статус: отключён",
            VPNState.CONNECTING: "Статус: подключение...",
            VPNState.CONNECTED: "Статус: подключено",
            VPNState.ERROR: "Статус: ошибка",
        }
        self.status.setText(labels[state])
        active = state in (VPNState.CONNECTING, VPNState.CONNECTED)
        self.connect_button.setEnabled(not active)
        self.disconnect_button.setEnabled(active)
