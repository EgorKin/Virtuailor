import idc
import idautils
import idaapi


def get_segment_ranges(segment_names):
    segment_ranges = []
    for s in idautils.Segments():
        if idc.SegName(s) in segment_names:
            segment_ranges.append((idc.SegStart(s), idc.SegEnd(s)))
    return segment_ranges


# from lazyida
class action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hotkey actions
    """

    def __init__(self, callback):
        idaapi.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):
        self.callback(ctx)
        return 1

    def update(self, ctx):
        if idaapi.IDA_SDK_VERSION >= 770:
            target_attr = "widget_type"
        else:
            target_attr = "form_type"

        if idaapi.IDA_SDK_VERSION >= 900:
            dump_type = idaapi.BWN_HEXVIEW
        else:
            dump_type = idaapi.BWN_DUMP

        if ctx.__getattribute__(target_attr) in (idaapi.BWN_DISASM, dump_type):
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET


def register_action(name, description, callback, shortcut=None):
    idaapi.register_action(
        idaapi.action_desc_t(name, description, action_handler_t(callback), shortcut)
    )
