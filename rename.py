from os import rename
import idc
import idaapi
import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

# LSP
import utils

# from utils import get_segment_ranges
idaapi.require("utils")


def reset_local_type(id, decl):
    if idc.set_local_type(id, None, 0) == 0:
        raise Exception("reset_local_type: Failed to reset local type")
    if idc.set_local_type(id, decl, 0) == 0:
        raise Exception("reset_local_type: Failed to set local type")


def rename_local_type(id, new_name):
    decl = idc.print_decls(str(id), 0)
    if "struct" not in decl:
        raise Exception("rename_local_type: print_decls failed, got `" + decl + "`")
    decl = "struct " + new_name + decl[decl.find("{") :]
    reset_local_type(id, decl)


def rename_object(obj_name, new_obj_name):
    # find obj local type and obj::vptr local type id
    vtable_name = obj_name + "::vtable"
    obj_id, vtable_id = None, None
    for id in range(idc.get_ordinal_qty()):
        if idc.get_numbered_type_name(id) == obj_name:
            obj_id = id
        elif idc.get_numbered_type_name(id) == vtable_name:
            vtable_id = id
            if obj_id is None:
                raise Exception("obj_id not found")
            break
    rename_local_type(obj_id, new_obj_name)
    vtable_decl = idc.print_decls(str(vtable_id), 0)
    vtable_decl = vtable_decl.replace(obj_name + "::", new_obj_name + "::")
    reset_local_type(vtable_id, vtable_decl)
    # other vtables might also have func ptr of obj_name
    for id in range(idc.get_ordinal_qty()):
        decl = idc.print_decls(str(id), 0)
        if obj_name + "::" in decl:
            decl = decl.replace(obj_name + "::", new_obj_name + "::")
            reset_local_type(id, decl)

    text_seg_st, text_seg_ed = utils.get_segment_ranges([".text"])[0]
    cur = idc.get_next_func(text_seg_st)
    while cur < text_seg_ed:
        func_name = idc.get_func_name(cur)
        if func_name.startswith(obj_name + "::"):
            idc.set_name(cur, new_obj_name + "::" + func_name[len(obj_name) + 2 :])
        func_cmt = idc.get_func_cmt(cur, 0)
        if obj_name in func_cmt:
            idc.set_func_cmt(cur, func_cmt.replace(obj_name, new_obj_name), 0)
        cur = idc.get_next_func(cur)


def rename_func(func_addr, old_name, new_name):
    idc.set_name(func_addr, new_name)
    for id in range(idc.get_ordinal_qty()):
        decl = idc.print_decls(str(id), 0)
        if old_name in decl:  # ignore vtable ::_{n}:: case
            decl = decl.replace(old_name, new_name)
            reset_local_type(id, decl)


class RenameFunctionGUI(QtWidgets.QDialog):
    def __init__(self):
        QtWidgets.QDialog.__init__(
            self,
            None,
            QtCore.Qt.WindowSystemMenuHint
            | QtCore.Qt.WindowTitleHint
            | QtCore.Qt.WindowCloseButtonHint,
        )
        self.setWindowTitle("Rename Function")
        self.setFixedWidth(800)
        layout = QtWidgets.QVBoxLayout()

        ea = idc.here()
        self.func_addr = idaapi.get_func(ea).start_ea
        func_name = idc.get_func_name(self.func_addr)
        self.old_name = func_name
        if not func_name:
            raise Exception(
                "RenameFunctionGUI: Failed to get function name at" + hex(ea)
            )

        sep_idx = func_name.rfind("::")
        if sep_idx == -1:
            self.scope = ""
            self.basename = func_name
        else:
            self.scope = func_name[: sep_idx + 2]
            self.basename = func_name[sep_idx + 2 :]

        spacer = QtWidgets.QSpacerItem(
            0, 8, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding
        )

        layout.addItem(spacer)
        row_layout = QtWidgets.QHBoxLayout()
        scope_label = QtWidgets.QLabel()
        scope_label.setText(self.scope)
        row_layout.addWidget(scope_label)

        self.func_name_area = QtWidgets.QLineEdit()
        self.func_name_area.setText(self.basename)
        self.func_name_area.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred
        )
        row_layout.addWidget(self.func_name_area)
        layout.addLayout(row_layout)

        # cannot register one widget twice, causing crash
        spacer2 = QtWidgets.QSpacerItem(
            0, 8, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding
        )
        layout.addItem(spacer2)

        button_ok = QtWidgets.QPushButton("&OK")
        button_ok.setDefault(True)
        button_ok.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred
        )
        button_ok.clicked.connect(self.on_ok_clicked)
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(button_ok)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def on_ok_clicked(self):
        new_basename = str(self.func_name_area.text())
        if self.basename != new_basename:
            if self.scope:
                new_name = self.scope + new_basename
            else:
                new_name = new_basename
            print("Renaming `" + self.old_name + "` to `" + new_name + "`")
            rename_func(self.func_addr, self.old_name, new_name)

        self.close()


# <class 'ida_kernwin.action_activation_ctx_t'>
# ['__class__', '__del__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__',
# '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__swig_destroy__', '__weakref__', '_get_form_type', '_get_reg', 'action',
# 'chooser_selection', 'cur_ea', 'cur_enum', 'cur_extracted_ea', 'cur_fchunk', 'cur_flags', 'cur_func', 'cur_seg', 'cur_strmem', 'cur_struc', 'focus', 'form_type',
# 'has_flag', 'reg', 'reserved', 'reset', 'this', 'thisown', 'widget', 'widget_title', 'widget_type']


def rename_function_gui(ctx):
    gui = RenameFunctionGUI()
    gui.exec_()


ida_kernwin.update_action_shortcut("OpUserOffset", "")  # Ctrl+R
utils.register_action(
    "renamefunction",
    "Rename function",
    rename_function_gui,
    "Ctrl-R",
    [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE],
)
