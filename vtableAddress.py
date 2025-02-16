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


def parse_arm_dereference(opnd):
    """
    [R2,#0xC] -> R2, "0xC"
    [R2,#0xC]! -> R2, "0xC"
    [R2],#0xC -> R2
    [R2,R3] -> R2, R3
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
        register = stripped[:sep_idx]
        if stripped[sep_idx + 1] == "#":
            offset = stripped[sep_idx + 2 :]
        else:
            offset = stripped[sep_idx + 1 :]  # [R1,R3]
    else:
        register = stripped
        offset = "0"
        # if register not in REGS:  # not sure if this is possible # checked at finally
        #    return None, None
    return register, offset


def back_search_deref(start_addr, end_addr, target_reg, offset_must_number=True):
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
    cur_addr = start_addr
    tmp_stack_addr = None
    while cur_addr >= end_addr:
        mnem = idc.GetMnem(cur_addr)
        if not tmp_stack_addr:
            if mnem.startswith("LDR") and idc.GetOpnd(cur_addr, 0) == target_reg:
                opnd2 = idc.GetOpnd(cur_addr, 1)
                base_register, offset = parse_arm_dereference(opnd2)
                if base_register is None:  # unsupported deref
                    return None
                elif base_register == "SP":
                    # load virtual func from stack, lookup happens before
                    tmp_stack_addr = opnd2
                else:
                    if offset_must_number and offset[0] == "R":
                        return None
                    return cur_addr, base_register, offset

            elif mnem.startswith("MOV") and idc.GetOpnd(cur_addr, 0) == target_reg:
                target_reg = idc.GetOpnd(cur_addr, 1)
                if target_reg not in REGS:
                    return None
        else:
            if mnem.startswith("STR") and idc.GetOpnd(cur_addr, 1) == tmp_stack_addr:
                target_reg = idc.GetOpnd(cur_addr, 0)
                tmp_stack_addr = None

        cur_addr = idc.PrevHead(cur_addr)


def get_con2_var_or_num_arm(func_reg, call_addr):
    start_addr = idc.GetFunctionAttr(call_addr, idc.FUNCATTR_START)
    ret = back_search_deref(idc.PrevHead(call_addr), start_addr, func_reg)
    if not ret:
        return None, None
    ref_vtable_addr, vtable_register, vtable_offset = ret
    ret = back_search_deref(idc.PrevHead(ref_vtable_addr), start_addr, vtable_register)
    if not ret:
        return (
            "VTABLE",
            {
                "ref_vtable_addr": ref_vtable_addr,
                "vtable_register": vtable_register,
                "vtable_offset": vtable_offset,
            },
        )
    ref_vptr_addr, vptr_register, vptr_offset = ret
    ret = back_search_deref(
        idc.PrevHead(ref_vtable_addr),
        start_addr,
        vtable_register,
        offset_must_number=False,
    )
    if not ret:
        return (
            "VPTR",
            {
                "ref_vptr_addr": ref_vptr_addr,
                "ref_vtable_addr": ref_vtable_addr,
                "vptr_register": vptr_register,
                "vtable_register": vtable_register,
                "vptr_offset": vptr_offset,
                "vtable_offset": vtable_offset,
            },
        )
    ref_objptr_addr, objptr_register, objptr_offset = ret  # offset can be register
    return (
        "OBJPTR",
        {
            "ref_objptr_addr": ref_objptr_addr,
            "ref_vptr_addr": ref_vptr_addr,
            "ref_vtable_addr": ref_vtable_addr,
            "objptr_register": objptr_register,
            "vptr_register": vptr_register,
            "vtable_register": vtable_register,
            "objptr_offset": objptr_offset,
            "vptr_offset": vptr_offset,
            "vtable_offset": vtable_offset,
        },
    )
    # return "out of the function", "-1", cur_addr


ARG_NAMES = [
    "ref_objptr_addr",
    "ref_vptr_addr",
    "ref_vtable_addr",
    "objptr_register",
    "vptr_register",
    "vtable_register",
    "objptr_offset",
    "vptr_offset",
    "vtable_offset",
]


def get_bp_condition(args):

    cond = BP_COND_TEXT
    for key in ARG_NAMES:
        cond = cond.replace("<<<" + key + ">>>", str(args.get(key, None)))
    return cond


def write_vtable2file(call_addr, raw_opnd):
    reg = raw_opnd
    ret_code, args = get_con2_var_or_num_arm(reg, call_addr)
    if not ret_code:
        return "", -1

    bp_addr = args["ref" + ret_code.lower() + "_addr"]
    args["call_addr"] = call_addr
    bp_cond = get_bp_condition(args)
    return bp_cond, bp_addr
