import functools
import xmlrpc.client


def only_if_connected(f):
    @functools.wraps(f)
    def _only_if_connected(self, *args, **kwargs):
        if self.connected:
            return f(self, *args, **kwargs)

    return _only_if_connected


class DecompilerClient:
    def __init__(self, name="decompiler", host="localhost", port=3662, native_sym_support=True):
        self.name = name
        self.host = host
        self.port = port
        self.native_sym_support = native_sym_support
        self.server = None

    #
    # Server Ops
    #

    @property
    def connected(self):
        return True if self.server else False

    def connect(self, name=None, host=None, port=None) -> bool:
        """
        Connects to the remote decompiler.
        """
        self.name = name or self.name
        host = host or self.host
        port = port or self.port

        # create a decompiler server connection and test it
        retry = True
        try:
            self.server = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(host, port))
            self.server.ping()
            retry = False
        except:
            pass

        # the connection could fail because its a Ghidra connection on endpoint d2d
        if retry:
            try:
                self.server = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(host, port)).d2d
                self.server.ping()
            except (ConnectionRefusedError, AttributeError) as e:
                self.server = None
                # if we fail here, we fail overall
                return False

        self.decompiler_connected()
        return True

    def decompiler_connected(self):
        pass

    def decompiler_disconnected(self):
        pass

    #
    # Decompiler Interface
    #

    @only_if_connected
    def disconnect(self):
        try:
            self.server.disconnect()
        except Exception:
            pass

        self.server = None
        self.decompiler_disconnected()

    @only_if_connected
    def decompile(self, addr):
        return self.server.decompile(addr)

    @only_if_connected
    def function_data(self, addr):
        return self.server.function_data(addr)

    @property
    @only_if_connected
    def function_headers(self):
        return self.server.function_headers()

    @property
    @only_if_connected
    def global_vars(self):
        return self.server.global_vars()

    @property
    @only_if_connected
    def structs(self):
        return self.server.structs()

    @property
    @only_if_connected
    def breakpoints(self):
        return self.server.breakpoints()

    #
    # Client Setters
    #

    def update_global_vars(self):
        raise NotImplementedError

    def update_function_headers(self):
        raise NotImplementedError

    def update_function_data(self, addr):
        raise NotImplementedError
