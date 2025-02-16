import idc
import idautils
import ida_frame
import ida_struct
import idaapi
import sys, os

idaapi.require("AddBP")

# fmt: off
REGISTERS = {
"ARM": {
    False:["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14"],
    True:["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29", "X30", "X31"]
},
"Intel": {
    False:["eax", "ebx", "ecx", "edx"], 
    True:["rax", "rbx", "rcx", "rdx", "r9", "r10", "r8"]},
}

CALL_INSTRUCTION = {
    "ARM": {False: "BLX", True: "BLR"},
    "Intel": {False: "call", True:"call"}
}
# fmt: on


def get_processor_architecture():
    arch = "Intel"
    info = idaapi.get_inf_structure()
    if info.procName == "ARM":
        arch = "ARM"
    if info.is_64bit():
        return arch, True
    elif info.is_32bit():
        return arch, False
    else:
        return "Error", False


def _get_call_instruction(arch, is_64):
    return CALL_INSTRUCTION[arch][is_64]


def _get_registers(arch, is_64):
    return REGISTERS[arch][is_64]


def _get_arch_dct(arch, is_64):
    # arch, is_64 = get_processor_architecture()
    if arch != "Error" or (arch == "ARM" and not is_64):
        dct_arch = {}
        if arch == "ARM":
            dct_arch["opcode"] = "LDR"
            dct_arch["separator"] = ","
            dct_arch["val_offset"] = 2
        if arch == "Intel":
            dct_arch["opcode"] = "mov"
            dct_arch["separator"] = "+"
            dct_arch["val_offset"] = 1
        return dct_arch
    else:
        print(
            "Error, Architecture is not supported. Supported architectures are Intel x64/x32 and Arm x64"
        )
        return -1


arch, is_64 = get_processor_architecture()
assert arch != "Error"
CALL_INSTR = _get_call_instruction(arch, is_64)
REGS = _get_registers(arch, is_64)
ARCH_DICT = _get_arch_dct(arch, is_64)
assert ARCH_DICT != -1


def read_bp_cond_text():
    file_name = "BPCond.py"
    if arch == "Intel":
        if is_64:
            file_name = "BPCond64.py"
    else:  # ARM
        if is_64:
            file_name = "BPCondAarch64.py"
        else:
            file_name = "BPCondArm.py"
    condition_file = os.path.join(
        os.path.dirname(os.path.abspath(sys.argv[0])), file_name
    )
    if arch != "Error" or (arch == "ARM" and not is_64):
        with open(condition_file, "rb") as f1:
            bp_cond_text = f1.read()
            return bp_cond_text
    return ""


BP_COND_TEXT = read_bp_cond_text()
assert BP_COND_TEXT != ""


def get_local_var_value_64(loc_var_name):
    frame = ida_frame.get_frame(idc.here())
    loc_var = ida_struct.get_member_by_name(frame, loc_var_name)
    loc_var_start = loc_var.soff
    loc_var_ea = loc_var_start + idc.GetRegValue("RSP")
    loc_var_value = idc.read_dbg_qword(
        loc_var_ea
    )  # in case the variable is 32bit, just use get_wide_dword() instead
    return loc_var_value


def get_con2_var_or_num_intel(func_reg, call_addr):
    start_addr = idc.GetFunctionAttr(call_addr, idc.FUNCATTR_START)
    cur_addr = idc.PrevHead(call_addr)
    while cur_addr >= start_addr:
        mnem = idc.GetMnem(cur_addr)
        if (
            mnem.startswith(ARCH_DICT["opcode"])
            and idc.GetOpnd(cur_addr, 0) == func_reg
        ):  # TODO lea ?
            opnd2 = idc.GetOpnd(cur_addr, 1)
            place = opnd2.find(ARCH_DICT["separator"])
            if place != -1:  # if the function is not the first in the vtable
                register = opnd2[opnd2.find("[") + 1 : place]
                if opnd2.find("*") == -1:
                    offset = opnd2[place + ARCH_DICT["val_offset"] : opnd2.find("]")]
                else:
                    offset = "*"
                return register, offset, cur_addr
            else:
                offset = "0"
                if opnd2.find("]") != -1:
                    register = opnd2[opnd2.find("[") + 1 : opnd2.find("]")]
                else:
                    register = opnd2
                return register, offset, cur_addr
        elif mnem.startswith("call"):
            intr_func_name = idc.GetOpnd(cur_addr, 0)
            # In case the code has CFG -> ignores the function call before the virtual calls
            if "guard_check_icall_fptr" not in intr_func_name:
                if "nullsub" not in intr_func_name:
                    # intr_func_name = idc.Demangle(intr_func_name, idc.GetLongPrm(idc.INF_SHORT_DN))
                    print(
                        "Warning! At address 0x%08x: The vtable assignment might be in another function (Maybe %s),"
                        " could not place BP." % (call_addr, intr_func_name)
                    )
                cur_addr = start_addr
        cur_addr = idc.PrevHead(cur_addr)
    return "out of the function", "-1", cur_addr


def parse_arm_dereference(opnd):
    """
    [R2,#0xC] -> R2, "0xC"
    [R2,#0xC]! -> R2, "0xC"
    [R2],#0xC -> R2
    [R2] -> R2, "0"
    LDR.W           R0, [R5],#8 (only [R5] will be passed in)
    other format -> None, None
    Not supported:
    LDR R0, [R1, R2, LSL#n]
    """
    if opnd[0] == "[" and not "LSL" in opnd:
        stripped = opnd[1 : opnd.index("]")]
    else:
        return None, None
    sep_idx = stripped.find(",")

    if sep_idx != -1:
        if stripped[sep_idx + 1] != "#":  # offset not constant (GOT call): [R1,R3]
            return None, None
        register = stripped[:sep_idx]
        offset = stripped[sep_idx + 2 :]
    else:
        register = stripped
        offset = "0"
        # if register not in REGS:  # not sure if this is possible # checked at finally
        #    return None, None
    return register, offset


def get_con2_var_or_num_arm(func_reg, call_addr):
    """
    Also handle cases like this:
    .text:0020FE3A                 LDR             R2, [R1] (TODO: break here to type class object ptr R1)
    .text:0020FE3C                 LDR             R2, [R2,#0xC] ; load virtual func from vtable (target)
    .text:0020FE3E                 LDR.W           R12, [SP,#0x98+var_34]
    .text:0020FE42                 LDR.W           LR, [SP,#0x98+var_48]
    .text:0020FE46                 STR             R0, [SP,#0x98+var_7C]
    .text:0020FE48                 MOV             R0, R1
    .text:0020FE4A                 MOV             R1, LR
    .text:0020FE4C                 STR             R2, [SP,#0x98+var_80] ; store virtual func to stack
    .text:0020FE4E                 MOV             R2, R12
    .text:0020FE50                 LDR.W           R12, [SP,#0x98+var_80] ; load virtual func from stack
    .text:0020FE54                 STR             R3, [SP,#0x98+var_84]
    .text:0020FE56                 BLX             R12
    """
    start_addr = idc.GetFunctionAttr(call_addr, idc.FUNCATTR_START)
    cur_addr = idc.PrevHead(call_addr)
    tmp_stack_addr = None
    while cur_addr >= start_addr:
        mnem = idc.GetMnem(cur_addr)
        if not tmp_stack_addr:
            if mnem.startswith("LDR") and idc.GetOpnd(cur_addr, 0) == func_reg:
                opnd2 = idc.GetOpnd(cur_addr, 1)
                vtable_register, vtable_offset = parse_arm_dereference(opnd2)
                if vtable_register is None:
                    return None
                elif (
                    vtable_register == "SP"
                ):  # load virtual func from stack, lookup happens before
                    tmp_stack_addr = opnd2
                else:  # found!, track object ptr dereference
                    deref_vptr_addr = cur_addr
                    cur_addr = idc.PrevHead(cur_addr)
                    # FIXME: currently object deref must exactly before vtable deref
                    #        a while is not safe enough
                    while cur_addr >= start_addr:
                        mnem = idc.GetMnem(cur_addr)
                        if (
                            mnem.startswith("LDR")
                            and idc.GetOpnd(cur_addr, 0) == vtable_register
                        ):
                            opnd2 = idc.GetOpnd(cur_addr, 1)
                            obj_register, obj_offset = parse_arm_dereference(opnd2)
                            if obj_register is None:
                                return None
                            else:
                                deref_obj_addr = cur_addr
                                for _ in range(5):
                                    cur_addr = idc.PrevHead(cur_addr)
                                    mnem = idc.GetMnem(cur_addr)
                                    if mnem.startswith("BL"):
                                        break
                                    elif (
                                        mnem.startswith("LDR")
                                        and idc.GetOpnd(cur_addr, 0) == obj_register
                                    ):
                                        for r in idautils.XrefsFrom(cur_addr):
                                            if r.type == idc.dr_R and r.user == 0:
                                                return (
                                                    deref_vptr_addr,
                                                    deref_obj_addr,
                                                    r.to,
                                                    vtable_register,
                                                    obj_register,
                                                    vtable_offset,
                                                    obj_offset,
                                                )
                                return None  # TODO
                        cur_addr = idc.PrevHead(cur_addr)
                    print(call_addr, "not after obj deref")
                    return None

            elif mnem.startswith("MOV") and idc.GetOpnd(cur_addr, 0) == func_reg:
                func_reg = idc.GetOpnd(cur_addr, 1)
                if func_reg not in REGS:
                    return None
        else:
            if mnem.startswith("STR") and idc.GetOpnd(cur_addr, 1) == tmp_stack_addr:
                func_reg = idc.GetOpnd(cur_addr, 0)
                tmp_stack_addr = None

        cur_addr = idc.PrevHead(cur_addr)
    return None
    # return "out of the function", "-1", cur_addr


# TODO: fix for load from memory
# def get_con2_var_or_num(call_reg, call_addr):
#    if arch == "Intel":
#        return get_con2_var_or_num_intel(call_reg, call_addr)
#    else:
#        return get_con2_var_or_num_arm(call_reg, call_addr)


def get_bp_condition(
    call_addr,
    deref_vptr_addr,
    deref_obj_addr,
    objptr_addr,
    vtable_register,
    object_register,
    vtable_offset,
    object_offset,
):

    return (
        BP_COND_TEXT.replace("<<<call_addr>>>", str(call_addr))
        .replace("<<<deref_vptr_addr>>>", str(deref_vptr_addr))
        .replace("<<<deref_obj_addr>>>", str(deref_obj_addr))
        .replace("<<<objptr_addr>>>", str(objptr_addr))
        .replace("<<<vtable_register>>>", vtable_register)
        .replace("<<<object_register>>>", object_register)
        .replace("<<<vtable_offset>>>", vtable_offset)
        .replace("<<<object_offset>>>", object_offset)
    )


def write_vtable2file(call_addr, raw_opnd):
    """
     :param start_addr: The start address of the virtual call
    :return: The break point condition and the break point address
    """
    # raw_opnd = idc.GetOpnd(start_addr, 0)
    reg = raw_opnd
    ret = get_con2_var_or_num_arm(reg, call_addr)
    if not ret:
        return "", -1
    (
        deref_vptr_addr,
        deref_obj_addr,
        objptr_addr,
        vtable_register,
        object_register,
        vtable_offset,
        object_offset,
    ) = ret
    if vtable_register in REGS:
        cond = get_bp_condition(
            call_addr,
            deref_vptr_addr,
            deref_obj_addr,
            objptr_addr,
            vtable_register,
            object_register,
            vtable_offset,
            object_offset,
        )
        return cond, deref_obj_addr
    return "", -1
