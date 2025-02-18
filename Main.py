import idc
import idautils
import idaapi

idaapi.require("AddBP")
idaapi.require("vtableAddress")
idaapi.require("GUI")

# for LSP only
import AddBP
import vtableAddress
import GUI


def get_all_functions():
    for func in idautils.Functions():
        print(hex(func), idc.GetFunctionName(func))


def get_xref_code_to_func(func_addr):
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.GetFunctionAttr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = idc.GetFunctionName(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls(cur_addr, end):
    CALL_INSTR = vtableAddress.CALL_INSTR
    REGS = vtableAddress.REGS
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.GetMnem(cur_addr) == CALL_INSTR:
            operand = idc.GetOpnd(cur_addr, 0)
            # print(
            #    "Virtual Call " + call_instr + " " + operand + " at: " + hex(cur_addr)
            # )
            # print("reg0", idc.GetOpnd(cur_addr, 0))
            # if True in [
            #    idc.GetOpnd(cur_addr, 0).find(reg) != -1 for reg in registers
            # ]:  # call involving a register, but we can't handle operations on the register
            if idc.GetOpnd(cur_addr, 0) in REGS:  # ensure a register only call
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr, operand)
                if cond != "":
                    bp_vtable = AddBP.add(bp_address, cond)
                    # print("BP added at: ", hex(bp_address))
        cur_addr = idc.NextHead(cur_addr)


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
    start_addr = (
        idc.MinEA()  # 0x20FE74  # You can change the virtual calls address range
    )
    end_addr = idc.MaxEA()  # 0x20FE7A
    start_addr_str = hex(start_addr)
    end_addr_str = hex(end_addr)
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
