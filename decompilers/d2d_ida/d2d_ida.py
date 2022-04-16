def PLUGIN_ENTRY(*args, **kwargs):
    from d2d_ida.plugin import Decomp2DBGPlugin

    return Decomp2DBGPlugin(*args, **kwargs)
