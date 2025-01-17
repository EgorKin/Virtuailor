virtual_call_addr,register_vtable,offset = str(<<<start_addr>>>),"<<<register_vtable>>>", <<<offset>>>

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
        #if code_err == 0:
            #print "Failed to create code, at", hex(vfunc_addr)
        #elif not func_err:
            #print "Failed to create function, at". hex(vfunc_addr)

def get_fixed_name_for_object(address, prefix=""):
    v_func_name = idc.GetFunctionName(int(address))
    calc_func_name = int(address) - base #idc.SegStart(int(address))
    #v_func_name =  prefix + str(calc_func_name)
    if v_func_name[:4] == "sub_":
        v_func_name =  prefix + str(calc_func_name)
    elif v_func_name == "":
        v_func_name =  prefix + str(calc_func_name)
    return v_func_name

def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    print("get_vtable_and_vfunc_addr")
    if is_brac == -1:
        p_vtable_addr = idc.GetRegValue(register_vtable)
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = idc.read_dbg_dword(pv_func_addr)  # Use dword for 32-bit
        return p_vtable_addr, v_func_addr
    else:
        p_vtable_addr = idc.read_dbg_dword(idc.GetRegValue(register_vtable))  # Use dword for 32-bit
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = idc.read_dbg_dword(pv_func_addr)  # Use dword for 32-bit
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
    vtable_func_value = idc.read_dbg_dword(p_vtable_addr)  # Use dword for 32-bit
    while vtable_func_value != 0:
        try:
            fix_arm_vtable(vtable_func_value)
        except:
            pass
        print("65: vtable_func_value:", vtable_func_value)
        v_func_name = idc.GetFunctionName(vtable_func_value)
        if v_func_name == '':
            vtable_func_value = idc.read_dbg_dword(vtable_func_value)  # Use dword for 32-bit
            print("69: vtable_func_value:", vtable_func_value)
            v_func_name = idc.GetFunctionName(vtable_func_value)
            if v_func_name == '':
                print("Error in adding functions to struct, at BP address::", hex(start_address))
        v_func_name = get_fixed_name_for_object(int(vtable_func_value), "vfunc_")
        idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , idc.FF_DWRD, -1, 4)  # Use dword for 32-bit
        vtable_func_offset += 4  # Use 4 bytes for 32-bit
        vtable_func_value = idc.read_dbg_dword(p_vtable_addr + vtable_func_offset)  # Use dword for 32-bit
        if vtable_func_value == 0 or vtable_func_value >> 24 == 0xff:
            break

def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    print("create_vtable_struct")
    struct_name = vtable_name + "_struct"
    struct_id = idc.add_struc(-1, struct_name, 0)
    if struct_id != idc.BADADDR:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("pc"))), 1, struct_id)
    else:
        struct_id = idc.GetStrucIdByName(struct_name)
        if struct_id != idc.BADADDR:
            idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("pc"))), 1, struct_id)
        else:
            print("Failed to create struct: " +  struct_name)

def do_logic(virtual_call_addr, register_vtable, offset):
    is_brac_assign = idc.GetOpnd(int(idc.GetRegValue("pc")), 1).find('[')
    #base = idc.SegStart(int(idc.GetRegValue("pc")))
    print("base:", hex(base))
    call_addr = int(virtual_call_addr) + base
    is_brac_call = idc.GetOpnd(call_addr, 0).find('[')
    is_brac = -1
    if is_brac_assign != -1 and is_brac_call != -1:
        is_brac = 0
    p_vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(is_brac, register_vtable, offset)
    print("p_vtable_addr:", hex(p_vtable_addr), "v_func_addr:", hex(v_func_addr))
    v_func_name = get_fixed_name_for_object(v_func_addr, "vfunc_")
    idaapi.set_name(v_func_addr, v_func_name, idaapi.SN_FORCE)
    vtable_name = get_fixed_name_for_object(p_vtable_addr, "vtable_")
    idaapi.set_name(p_vtable_addr, vtable_name, idaapi.SN_FORCE)
    try:
        idc.add_cref(call_addr, v_func_addr, idc.XREF_USER)
    except:
        print("Logging - xref to function at address:", hex(v_func_addr), ", from:", hex(v_func_addr) )
    # first arg for error message only, use 0 image base
    create_vtable_struct(int(virtual_call_addr), vtable_name, p_vtable_addr, offset)

if offset == "*":
    opnd2 = idc.GetOpnd(virtual_call_addr, 1)
    reg_offset = 0
    place = opnd2.find('+')
    if place != -1:
        sep = opnd2.find('*')
        if sep != -1:
            reg_offset = idc.GetRegValue(opnd2[place + 1: sep])
        register = opnd2[opnd2.find('[') + 1: place]
        if reg_offset:
            offset = opnd2[sep + 1: opnd2.find(']')]
            if offset.find('0x') != -1:
                int_offset = int(offset[offset.find('0x') +2:], 16)
            else:
                int_offset = int(offset)
            offset = int_offset * reg_offset
        else:
            offset = opnd2[place + 1: opnd2.find(']')]
try:
    do_logic(virtual_call_addr, register_vtable, offset)
except Exception as e:
    print(e)
    import traceback
    traceback.print_exc()
    print("Error! at BP address:", hex(idc.GetRegValue("pc")))