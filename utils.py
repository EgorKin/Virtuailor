from importlib.metadata import entry_points
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

    def activate(self, ctx):
        self.callback(ctx)
        return 1

    def update(self, ctx):
        if ctx.__getattribute__(self.target_attr) in self.enabled_views:
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET


class UI_Hook(idaapi.UI_Hooks):
    def __init__(self, entry_name, views, action):
        idaapi.UI_Hooks.__init__(self)
        self.views = views
        self.entry_name = entry_name
        self.action = action

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)
        if form_type in self.views:
            idaapi.attach_action_to_popup(form, popup, self.action, self.entry_name)


def register_action(name, description, callback, shortcut=None, views=[], popup=False):
    handler = action_handler_t(callback, views)
    idaapi.register_action(
        idaapi.action_desc_t(
            name,
            description,
            handler,
            shortcut,
        )
    )
    if popup:
        UI_Hook(name, views, handler).hook()
