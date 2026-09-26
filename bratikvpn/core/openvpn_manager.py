from enum import Enum
from pathlib import Path
from PyQt6.QtCore import QObject, QProcess, pyqtSignal


class VPNState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class OpenVPNManager(QObject):
    state_changed = pyqtSignal(object)
    log_line = pyqtSignal(str)

    def __init__(self, executable: Path, parent: QObject | None = None):
        super().__init__(parent)
        self.executable = executable
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)
        self._state = VPNState.DISCONNECTED

    @property
    def state(self) -> VPNState:
        return self._state

    def _set_state(self, state: VPNState) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)

    def connect_vpn(self, config_path: Path) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            return
        if not self.executable.exists():
            self._set_state(VPNState.ERROR)
            self.log_line.emit(f"OpenVPN не найден: {self.executable}")
            return
        if not config_path.exists():
            self._set_state(VPNState.ERROR)
            self.log_line.emit(f"Конфигурация не найдена: {config_path}")
            return

        self._set_state(VPNState.CONNECTING)
        self.log_line.emit(f"Запуск OpenVPN с конфигурацией: {config_path.name}")
        self.process.start(str(self.executable), ["--config", str(config_path)])

    def disconnect(self) -> None:
        if self.process.state() == QProcess.ProcessState.NotRunning:
            self._set_state(VPNState.DISCONNECTED)
            return
        self.log_line.emit("Остановка OpenVPN...")
        self.process.terminate()
        if not self.process.waitForFinished(5000):
            self.process.kill()

    def _read_output(self) -> None:
        output = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        for line in output.splitlines():
            self.log_line.emit(line)
            if "Initialization Sequence Completed" in line:
                self._set_state(VPNState.CONNECTED)

    def _process_finished(self, exit_code: int, _status) -> None:
        if self._state != VPNState.ERROR:
            self._set_state(VPNState.DISCONNECTED)
        self.log_line.emit(f"OpenVPN завершён, код: {exit_code}")

    def _process_error(self, error) -> None:
        self._set_state(VPNState.ERROR)
        self.log_line.emit(f"Ошибка процесса OpenVPN: {error}")
