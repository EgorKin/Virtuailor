import idc
import idautils
import idaapi


def get_segment_ranges(segment_names):
    segment_ranges = []
    for s in idautils.Segments():
        if idc.SegName(s) in segment_names:
            segment_ranges.append((idc.SegStart(s), idc.SegEnd(s)))
    return segment_ranges


# ref: lazyida
class action_handler_t(idaapi.action_handler_t):
    def __init__(self, callback, enabled_views):
        idaapi.action_handler_t.__init__(self)
        self.callback = callback

        if idaapi.IDA_SDK_VERSION >= 770:
            self.target_attr = "widget_type"
        else:
            self.target_attr = "form_type"

        self.enabled_views = enabled_views
        if idaapi.IDA_SDK_VERSION >= 900:
            self.enabled_views.append(idaapi.BWN_HEXVIEW)
        else:
            self.enabled_views.append(idaapi.BWN_DUMP)

    def activate(self, ctx):
        self.callback(ctx)
        return 1

    def update(self, ctx):
        if ctx.__getattribute__(self.target_attr) in self.enabled_views:
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET


def register_action(name, description, callback, shortcut=None, views=[]):
    idaapi.register_action(
        idaapi.action_desc_t(
            name,
            description,
            action_handler_t(callback, views),
            shortcut,
        )
    )
