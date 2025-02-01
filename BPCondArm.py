virtual_call_addr, bp_addr ,register_vtable,offset = <<<start_addr>>>, <<<bp_addr>>>,"<<<register_vtable>>>", <<<offset>>>

import idc
import idaapi
import idautils

base = idaapi.get_imagebase()

def make_func(ea):
    code_err = idc.MakeCode(ea)
    func_err= idc.MakeFunction(ea)
    return code_err, func_err

def fix_arm_vtable(vfunc_addr):
    if not idc.is_code(vfunc_addr):
        code_err, func_err = make_func(vfunc_addr)
        if code_err == 0:
            print("Failed to create code, at", hex(vfunc_addr))
        elif not func_err:
            print("Failed to create function, at". hex(vfunc_addr))

def get_name(address):
    name = idc.GetFunctionName(address)
    if name == "":
        name = idc.Name(address)
        if name.startswith("_Z"):
            name = idc.Demangle(name, 0)[:name.find("(")] # strip off the arguments
    return name

def get_fixed_name_for_object(address, prefix=""):
    name = get_name(address)
    if name[:4] == "sub_" or name == "loc_" or name == "":
        addr_hex = hex(address - base)[2:-1] #idc.SegStart(int(address))
        if addr_hex[-1] == "L":
            addr_hex = addr_hex[:-1]
        name =  prefix + addr_hex
    return name # nullsub_

def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    #print("get_vtable_and_vfunc_addr")
    if is_brac == -1: # always
        p_vtable_addr = idc.GetRegValue(register_vtable)
    else:
        p_vtable_addr = idc.read_dbg_dword(idc.GetRegValue(register_vtable))  # Use dword for 32-bit

    pv_func_addr = p_vtable_addr + offset
    v_func_addr = idc.read_dbg_dword(pv_func_addr)  # Use dword for 32-bit
    v_func_addr = v_func_addr - 1 # thumb's
    return p_vtable_addr, v_func_addr

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
    return  succ1

def add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset):
    vtable_func_offset = 0

    # skip initial 0x0 (somehow happens to libart.so)
    while True:
        vtable_func_value = idc.read_dbg_dword(p_vtable_addr + vtable_func_offset)  # Use dword for 32-bit
        if vtable_func_value == 0:
            vtable_func_offset += 4
        else:
            break
    
    while True:
        vtable_func_value = idc.read_dbg_dword(p_vtable_addr + vtable_func_offset)  # Use dword for 32-bit
        if vtable_func_value == 0 or vtable_func_value >> 24 == 0xff:
            break

        if vtable_func_value & 1:
            vtable_func_value -= 1 # thumb's
        try:
            fix_arm_vtable(vtable_func_value)
        except:
            pass
        v_func_name = get_fixed_name_for_object(vtable_func_value, "vfunc_")
        if not v_func_name:
            print("GetFunctionName Error with", hex(vtable_func_value))
            print("bp address:", hex(bp_addr+base))
            print("vtable_addr", hex(p_vtable_addr))
            print("offset", offset)
            raise Exception("Error in adding functions to struct, at BP address::", hex(start_address))
        succ = idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        #print("set func name " + v_func_name + " at " + hex(vtable_func_value),succ)
        err = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , idc.FF_DWRD, -1, 4)  # Use dword for 32-bit
        # print("add_struc_member:",err==0)
        vtable_func_offset += 4  # Use 4 bytes for 32-bit
        

def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    #print("create_vtable_struct")
    struct_name = vtable_name + "_struct"
    struct_id = idc.add_struc(-1, struct_name, 0)
    if struct_id != -1:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("pc"))), 1, struct_id)
    else: # name is already taken
        struct_id = idc.GetStrucIdByName(struct_name)
        if struct_id != -1:
            idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("pc"))), 1, struct_id)
        else: # not likely
            print("Failed to create struct without name collision: " +  struct_name)

def do_logic(virtual_call_addr, register_vtable, offset):
    call_addr = virtual_call_addr + base
    is_brac = -1
    p_vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(is_brac, register_vtable, offset)
    vtable_name = get_fixed_name_for_object(p_vtable_addr, "vtable_")
    idaapi.set_name(p_vtable_addr, vtable_name, idaapi.SN_FORCE)
    # add xref at blx
    succ = idc.add_cref(call_addr, v_func_addr, idc.XREF_USER|idc.fl_CF) # blx register can be a far call
    if not succ:
        print("Logging - xref failed to function at address:" + hex(call_addr) + ", from:" + hex(v_func_addr) )
    # first arg for error message only, use 0 image base
    create_vtable_struct(virtual_call_addr, vtable_name, p_vtable_addr, offset)

try:
    do_logic(virtual_call_addr, register_vtable, offset)
    # disable after cond executed
    #print("Disabling BP at:", hex(bp_addr + base))
    idaapi.enable_bpt(bp_addr + base, False)
except Exception as e:
    print(e)
    import traceback
    traceback.print_exc()
    #print("Error! at BP address:", hex(idc.GetRegValue("pc")))
    return True