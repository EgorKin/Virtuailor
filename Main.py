import idc
import idautils
import idaapi
import ida_ida
import ida_funcs

idaapi.require("AddBP")
idaapi.require("vtableAddress")
idaapi.require("GUI")

# for LSP only
import AddBP
import vtableAddress
import GUI


def get_all_functions():
    for func in idautils.Functions():
        print(hex(func), ida_funcs.get_func_name(func))


def get_xref_code_to_func(func_addr):
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.get_func_attr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = ida_funcs.get_func_name(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls(cur_addr, end):
    CALL_INSTR = vtableAddress.CALL_INSTR
    REGS = vtableAddress.REGS
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.print_insn_mnem(cur_addr) == CALL_INSTR:
            operand = idc.print_operand(cur_addr, 0)

            print("Virtual Call " + str(CALL_INSTR) + " " + str(operand) + " at: " + hex(cur_addr))
            # print("reg0", idc.print_operand(cur_addr, 0))
            # if True in [
            #    idc.print_operand(cur_addr, 0).find(reg) != -1 for reg in registers
            # ]:  # call involving a register, but we can't handle operations on the register
            if idc.print_operand(cur_addr, 0) in REGS:  # ensure a register only call. может быть можно было idc.get_operand_type(cur_addr, 0) == idaapi.o_reg:
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr, operand)
                if cond != "":
                    bp_vtable = AddBP.add(bp_address, cond)
                    print("BP added at: ", hex(bp_address))
        cur_addr = idc.next_head(cur_addr)


def set_values(start, end):
    start = start
    end = end
    return start, end


def to_hex_str(num):
    s = hex(num)
    if s[-1] == "L":
        return s[2:-1]
    else:
        return s[2:]


if __name__ == "__main__":
    start_addr = ida_ida.inf_get_min_ea()  # You can change the virtual calls address range
    end_addr = ida_ida.inf_get_max_ea()
    oldTo = idaapi.set_script_timeout(0)
    # Initializes the GUI: Deletes the 0x in the beginning and the L at the end:
    gui = GUI.VirtuailorBasicGUI(
        set_values,
        {"start": to_hex_str(start_addr), "end": to_hex_str(end_addr)},
    )
    gui.exec_()
    if gui.start_line.text != "banana":
        add_bp_to_virtual_calls(
            int(gui.start_line.text(), 16), int(gui.stop_line.text(), 16)
        )
        vtableAddress.print_counter()
    with open("obj_count.txt", "w") as f:
        f.write("0")
    with open("failed_casts.py", "w") as f:
        pass
