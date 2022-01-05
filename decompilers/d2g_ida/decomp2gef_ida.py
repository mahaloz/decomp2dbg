def PLUGIN_ENTRY(*args, **kwargs):
    from d2g_ida.plugin import Decomp2GEFPlugin

    return Decomp2GEFPlugin(*args, **kwargs)
