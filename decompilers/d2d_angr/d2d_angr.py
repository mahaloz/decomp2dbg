#
# ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗██████╗ ██████╗ ██████╗ ██████╗  ██████╗
# ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔══██╗╚════██╗██╔══██╗██╔══██╗██╔════╝
# ██║  ██║█████╗  ██║     ██║   ██║██╔████╔██║██████╔╝ █████╔╝██║  ██║██████╔╝██║  ███╗
# ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔═══╝ ██║  ██║██╔══██╗██║   ██║
# ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██████╔╝██████╔╝╚██████╔╝
# ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═════╝ ╚═════╝  ╚═════╝
#                            angr-management server
#
# by clasm, 2021.
#

import threading
import traceback

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QGridLayout
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

from .server import AngrDecompilerServer

#
# UI
#


class ConfigDialog(QDialog):
    def __init__(self, instance, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Decomp2GEF")
        self._main_layout = QVBoxLayout()
        self._instance = instance
        self._host_edit = None  # type:QLineEdit
        self._port_edit = None  # type:QLineEdit

        self._init_widgets()
        self.setLayout(self._main_layout)
        self.show()

    def _init_widgets(self):
        upper_layout = QGridLayout()

        host_label = QLabel(self)
        host_label.setText("Host")
        self._host_edit = QLineEdit(self)
        self._host_edit.setText("localhost")
        row = 0
        upper_layout.addWidget(host_label, row, 0)
        upper_layout.addWidget(self._host_edit, row, 1)
        row += 1

        port_label = QLabel(self)
        port_label.setText("Port")
        self._port_edit = QLineEdit(self)
        self._port_edit.setText("3662")
        upper_layout.addWidget(port_label, row, 0)
        upper_layout.addWidget(self._port_edit, row, 1)
        row += 1

        # buttons
        self._ok_button = QPushButton(self)
        self._ok_button.setText("OK")
        self._ok_button.setDefault(True)
        self._ok_button.clicked.connect(self._on_ok_clicked)
        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(cancel_button)

        # main layout
        self._main_layout.addLayout(upper_layout)
        self._main_layout.addLayout(buttons_layout)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        host = self._host_edit.text()
        port = self._port_edit.text()

        if not host:
            QMessageBox(self).critical(None, "Invalid host",
                                       "Host cannot be empty."
                                       )
            return

        if not port:
            QMessageBox(self).critical(None, "Invalid port",
                                       "Port cannot be empty"
                                       )
            return

        decomp_server = AngrDecompilerServer(self._instance)
        t = threading.Thread(target=decomp_server.start_xmlrpc_server, kwargs={"host": host, "port": int(port, 0)})
        t.daemon = True
        try:
            t.start()
        except Exception as e:
            QMessageBox(self).critical(None, "Error starting Decomp2GEF Server", str(e))
            traceback.print_exc()
            return

        self.close()

    def _on_cancel_clicked(self):
        self.close()


class Decomp2DbgPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        """
        The entry point for the Decomp2Gef plugin.
        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)
        self._workspace = workspace
        self._instance = workspace.instance

    MENU_BUTTONS = ('Configure Decomp2GEF...', )
    MENU_CONFIG_ID = 0

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_config_dialog,
        }

        # call option mapped to each menu pos
        mapping.get(idx)()

    def open_config_dialog(self):
        if self.workspace.instance.project.am_none:
            # project does not exist yet
            return

        config = ConfigDialog(self._instance)
        config.exec_()
