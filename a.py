# often cause orphan comment
def set_hexrays_comment(address, text):
    """
    set comment in decompiled code
    """
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_BLOCK1
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts()


idc.set_cmt(address, text, 0)
