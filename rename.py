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


# TODO: rename object GUI


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
        layout = QtWidgets.QVBoxLayout()

        ea = idc.here()
        func_name = idc.get_func_name(ea)
        if not func_name:
            raise Exception(
                "RenameFunctionGUI: Failed to get function name at" + hex(ea)
            )

        sep_idx = func_name.rfind("::")
        scope = func_name[:sep_idx]
        name = func_name[sep_idx + 2 :]

        row_layout = QtWidgets.QHBoxLayout()
        scope_label = QtWidgets.QLabel()
        scope_label.setText(scope)
        row_layout.addWidget(scope_label)

        self.func_line = QtWidgets.QLineEdit()
        self.func_line.setText(func_name)
        self.func_line.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred
        )
        row_layout.addWidget(self.func_line)
        layout.addLayout(row_layout)

        spacer = QtWidgets.QSpacerItem(
            0, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding
        )
        layout.addItem(spacer)

        button_ok = QtWidgets.QPushButton("&OK")
        button_ok.setDefault(True)
        button_ok.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred
        )
        button_ok.clicked.connect(self.on_ok_clicked)
        layout.addWidget(button_ok)

        self.setLayout(layout)

    def on_ok_clicked(self):
        # TODO
        self.close()

    def closeEvent(self, event):
        self.close()


def rename_function(ctx):
    print(type(ctx))
    print(dir(ctx))
    gui = RenameFunctionGUI()
    gui.exec_()


ida_kernwin.update_action_shortcut("OpUserOffset", "")  # Ctrl+R
utils.register_action(
    "renamefunction",
    "Rename function",
    rename_function,
    "Ctrl-R",
    [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE],
)
utils.register_action(
    "renameobject",
    "Rename object",
    rename_function,
    None,
    [idaapi.BWN_LOCTYPS],
    True,
)
