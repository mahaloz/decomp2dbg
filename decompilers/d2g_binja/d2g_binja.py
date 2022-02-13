import threading
import traceback

try:
    from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, \
        QGridLayout
except ImportError:
    from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, \
        QGridLayout


from binaryninjaui import (
    UIContext,
    UIAction,
    UIActionHandler,
    Menu,
)

from .server import BinjaDecompilerServer

#
# UI
#

class ConfigDialog(QDialog):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.setWindowTitle("Configure Decomp2GEF")
        self._main_layout = QVBoxLayout()
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

        decomp_server = BinjaDecompilerServer(self.bv)
        t = threading.Thread(target=decomp_server.start_xmlrpc_server, kwargs={'host': host, 'port': int(port)})
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

#
# Plugin
#

class BinjaPlugin:
    def __init__(self):
        # controller stored by a binary view
        self._init_ui()

    def _init_ui(self):
        # config dialog
        configure_binsync_id = "Decomp2GEF: Configure"
        UIAction.registerAction(configure_binsync_id)
        UIActionHandler.globalActions().bindAction(
            configure_binsync_id, UIAction(self._launch_config)
        )
        Menu.mainMenu("Tools").addAction(configure_binsync_id, "Decomp2GEF")

    def _launch_config(self, bn_context):
        bv = bn_context.binaryView

        # configure
        dialog = ConfigDialog(bv)
        dialog.exec_()


BinjaPlugin()
