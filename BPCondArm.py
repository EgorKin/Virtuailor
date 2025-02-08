call_addr, bp_addr, register_vtable, register_object, offset = <<<start_addr>>>, <<<bp_addr>>>,"<<<register_vtable>>>", "<<<register_object>>>",<<<offset>>>

from os import error
import idc
import idaapi
import idautils
import ida_bytes

base = idaapi.get_imagebase()
call_addr+=base
bp_addr+=base

def error_print():
    print("bp address:", hex(bp_addr))

def append_cmt(ea, cmt, repeatable=0, add_repeated=False):
    cur_cmt = idc.get_cmt(ea, repeatable)
    if not add_repeated and cur_cmt and cmt in cur_cmt:
        return
    if cur_cmt:
        new_cmt = cur_cmt + "\n" + cmt
    else:
        new_cmt = cmt
    idc.set_cmt(ea, new_cmt, repeatable)

def is_code(ea):
    return idc.is_code(ida_bytes.get_flags(ea))

def make_func(ea):
    code_err = idc.MakeCode(ea)
    func_err = idc.MakeFunction(ea)
    return code_err, func_err


def fix_arm_vtable(vfunc_addr):
    if not is_code(vfunc_addr):
        code_err, func_err = make_func(vfunc_addr)
        if code_err == 0:
            print("Failed to create code, at", hex(vfunc_addr))
        elif not func_err:
            print("Failed to create function, at".hex(vfunc_addr))


def get_name(address):
    name = idc.GetFunctionName(address)
    if name == "":
        name = idc.Name(address)
        if name.startswith("_Z"):
            name = idc.Demangle(name, 0)[: name.find("(")]  # strip off the arguments
    return name


def get_fixed_name_for_object(address, prefix=""):
    name = get_name(address)
    if name[:4] == "sub_" or name == "loc_" or name == "":
        addr_hex = hex(address - base)[2:-1]  # idc.SegStart(int(address))
        if addr_hex[-1] == "L":
            addr_hex = addr_hex[:-1]
        name = prefix + addr_hex
    return name  # nullsub_ or already renamed


def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    # print("get_vtable_and_vfunc_addr")
    if is_brac == -1:  # always
        vtable_addr = idc.GetRegValue(register_vtable)
    else:
        vtable_addr = idc.read_dbg_dword(
            idc.GetRegValue(register_vtable)
        )  # Use dword for 32-bit

    pv_func_addr = vtable_addr + offset
    v_func_addr = idc.read_dbg_dword(pv_func_addr)  # Use dword for 32-bit
    v_func_addr = sub_one_if_thumb(v_func_addr)
    return vtable_addr, v_func_addr


def add_comment_to_struct_members(struct_id, vtable_func_offset, start_address):
    cur_cmt = idc.GetMemberComment(struct_id, vtable_func_offset, 1)
    new_cmt = ""
    if cur_cmt:
        if cur_cmt[:23] != "Was called from offset:":
            new_cmt = cur_cmt
        else:
            new_cmt = cur_cmt + ", " + start_address
    else:
        new_cmt = "Was called from offset: " + start_address
    succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, new_cmt, 1)
    return succ1


def sub_one_if_thumb(vtable_func_value):
    if vtable_func_value & 1:
        vtable_func_value -= 1  # thumb's
    return vtable_func_value

def gen_vtable_c_struct(name, fp_decls):
    struct = "struct " + name + " {\n"
    for fp_decl in fp_decls:
        struct += fp_decl+ ";\n"
    struct += "};\n"
    return struct

def get_func_ptr_type(vfunc_value, vfunc_name):
    d = idaapi.decompile(vfunc_value)
    t = idaapi.cfunc_type(d).dstr()
    ptr_str = "(*" + vfunc_name + ")("
    return t.replace("(", ptr_str, 1)

def create_vtable_struct(struct_name, vtable_addr, offset):
    v_func_offset = 0
    fp_decls = []

    # skip initial 0x0 (somehow happens to libart.so)
    # https://alschwalm.com/blog/static/2016/12/17/reversing-c-virtual-functions/
    # This is an eccentricity of newer versions of GCC. The compiler will replace
    # the destructor entries with NULL pointers in classes that have a pure-virtual 
    # method (i.e., classes that are abstract).

    while True:
        vfunc_value = idc.read_dbg_dword(
            vtable_addr + v_func_offset
        )  # Use dword for 32-bit
        if vfunc_value == 0:
            v_func_offset += 4
        else:
            break

    while True:
        vfunc_value = idc.read_dbg_dword(
            vtable_addr + v_func_offset
        )  # Use dword for 32-bit
        if vfunc_value == 0 or vfunc_value >> 24 == 0xFF:
            #TODO: use Offset to Top component (negative offset) to find the end of the vtable
            break

        vfunc_value = sub_one_if_thumb(vfunc_value)
        # try:
        #    fix_arm_vtable(vtable_func_value)
        # except:
        #    pass
        vfunc_name = get_fixed_name_for_object(vfunc_value, "vfunc_")
        if not vfunc_name:
            error_print()
            raise Exception(
                "GetFunctionName failed with " + hex(vfunc_value)
            )
        succ = idaapi.set_name(vfunc_value, vfunc_name, idaapi.SN_FORCE)
        fp_decl = get_func_ptr_type(vfunc_value, vfunc_name)
        fp_decls.append(fp_decl)
        #print(fp_decl, hex(vfunc_value))
        # can have nullsub (void (), directly return) or method don't use this (with no arg)
        # print("set func name " + vfunc_name + " at " + hex(vtable_func_value),succ)
        # TODO: construct vtable struct with function type & function name
        #err = idc.add_struc_member(
        #    struct_name, vfunc_name, v_func_offset, idc.FF_DWRD, -1, 4
        #)  # Use dword for 32-bit
        # print("add_struc_member:",err==0)
        v_func_offset += 4  # Use 4 bytes for 32-bit
    
    # create c struct declaration with fp_decls
    c_struct = gen_vtable_c_struct(struct_name, fp_decls)
    struct_id = idc.SetLocalType(-1, c_struct, 0)
    if struct_id == 0:
        error_print()
        raise Exception(
            "GetFunctionName failed with:\n" + c_struct
        )
    return struct_id
    


def cast_vtable_struct(vtable_name, vtable_addr, offset):
    # print("create_vtable_struct")
    struct_name = vtable_name + "_struct"
    #struct_id = idc.add_struc(-1, struct_name, 0)
    struct_id = idc.GetStrucIdByName(struct_name)
    if struct_id == idc.BADADDR: # not created yet
        struct_id = create_vtable_struct(struct_name, vtable_addr, offset)
    succ = idc.SetType(vtable_addr, struct_name)
    if not succ:
        error_print()
        raise Exception("SetType failed")
        
    idc.OpStroff(
        idautils.DecodeInstruction(int(idc.GetRegValue("pc"))), 1, struct_id
    )
    # add xref to vtable mem entry
    idc.add_dref(bp_addr, vtable_addr+offset, idc.XREF_USER|idc.dr_R)


def do_logic(call_addr, register_vtable, offset):
    vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(
        -1, register_vtable, offset
    )

    # v_func_addr possibly invalid
    # .text:CAEDF134 LDR.W           R2, [R5,#0x150]
    # .text:CAEDF138 CBZ             R2, loc_CAEDF146 (branch if zero)
    # .text:CAEDF13A LDR.W           R0, [R5,#0x154]
    # .text:CAEDF13E MOV             R1, R4
    # .text:CAEDF140 BLX             R2
    if not is_code(v_func_addr):
        return
        
    vtable_name = get_fixed_name_for_object(vtable_addr, "vtable_")
    idaapi.set_name(vtable_addr, vtable_name, idaapi.SN_FORCE)
    # rename the called vfunc first
    vfunc_name = get_fixed_name_for_object(v_func_addr, "vfunc_")
    idaapi.set_name(v_func_addr, vfunc_name, idaapi.SN_FORCE)
    idc.set_func_cmt(v_func_addr, vfunc_name+" @ "+vtable_name, 1)
    # add xref and cmt at blx
    succ = idc.add_cref(
        call_addr, v_func_addr, idc.XREF_USER | idc.fl_CF
    )  # blx register can be a far call
    #append_cmt(call_addr, vfunc_name, 0)

    if not succ:
        error_print()
        raise Exception(
            "xref failed to function at address:" + hex(call_addr) + " to " + hex(v_func_addr)
        )
    cast_vtable_struct(vtable_name, vtable_addr, offset)
    # TODO: retype object and vtable function


try:
    do_logic(call_addr, register_vtable, offset)
    # disable after cond executed
    # print("Disabling BP at:", hex(bp_addr + base))
    idaapi.enable_bpt(bp_addr, False)
except Exception as e:
    print(e)
    import traceback

    traceback.print_exc()
    # print("Error! at BP address:", hex(idc.GetRegValue("pc")))
    return True
