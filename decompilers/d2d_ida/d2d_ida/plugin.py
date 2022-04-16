#
# ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗██████╗ ██████╗ ██████╗ ██████╗  ██████╗
# ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔══██╗╚════██╗██╔══██╗██╔══██╗██╔════╝
# ██║  ██║█████╗  ██║     ██║   ██║██╔████╔██║██████╔╝ █████╔╝██║  ██║██████╔╝██║  ███╗
# ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔═══╝ ██║  ██║██╔══██╗██║   ██║
# ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██████╔╝██████╔╝╚██████╔╝
# ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═════╝ ╚═════╝  ╚═════╝
#

import traceback
import threading

from PyQt5.QtCore import QObject
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QGridLayout

import idaapi, ida_idp, ida_struct, idc, ida_enum

from .server import IDADecompilerServer

decomp_server: IDADecompilerServer = None


#
# Update Hooks
#

class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea) or ida_enum.get_enum_name(ea):
            return 0

        # renaming a function header
        ida_func = idaapi.get_func(ea)
        if ida_func and ida_func.start_ea == ea:
            decomp_server.cache["function_headers"][str(ea)]["name"] = new_name
            return 0

        # assume we are renaming a global var of some sort
        try:
            decomp_server.cache["global_vars"][str(ea)]["name"] = new_name
        except KeyError:
            # okay its not a global
            pass

        return 0


#
# UI
#

class ConfigDialog(QDialog):
    def __init__(self, change_hook, parent=None):
        super().__init__(parent)
        self.change_hook = change_hook
        self.setWindowTitle("Configure Decomp2DBG")
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
        global decomp_server

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

        decomp_server = IDADecompilerServer()
        t = threading.Thread(target=decomp_server.start_xmlrpc_server, kwargs={'host': host, 'port': int(port)})
        t.daemon = True
        try:
            t.start()
            # start hooks on good connection
            self.change_hook.hook()
        except Exception as e:
            QMessageBox(self).critical(None, "Error starting Decomp2DBG Server", str(e))
            traceback.print_exc()
            return

        self.close()

    def _on_cancel_clicked(self):
        self.close()


#
# Action Handlers
#

class IDAActionHandler(idaapi.action_handler_t):
    def __init__(self, action, plugin, typ):
        super(IDAActionHandler, self).__init__()
        self.action = action
        self.plugin = plugin
        self.typ = typ

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Decomp2DBGPlugin(QObject, idaapi.plugin_t):
    """Plugin entry point. Does most of the skinning magic."""

    flags = idaapi.PLUGIN_FIX
    comment = "Syncing decompiler info to GDB"
    help = "Decomp2DBG Help"
    wanted_name = "Decomp2DBG: configure"
    wanted_hotkey = "Ctrl-Shift-D"

    def __init__(self, *args, **kwargs):
        QObject.__init__(self, *args, **kwargs)
        idaapi.plugin_t.__init__(self)
        self.change_hook = IDBHooks()

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open_config_dialog()

    def open_config_dialog(self):
        dialog = ConfigDialog(self.change_hook)
        dialog.exec_()

    def term(self):
        pass

