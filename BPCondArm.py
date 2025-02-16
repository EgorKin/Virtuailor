mode = "<<<mode>>>"
call_addr, ref_objptr_addr, ref_vptr_addr, ref_vtable_addr = <<<call_addr>>>, <<<ref_objptr_addr>>>, <<<ref_vptr_addr>>>, <<<ref_vtable_addr>>>
objptr_register, vptr_register, vtable_register = "<<<objptr_register>>>", "<<<vptr_register>>>", "<<<vtable_register>>>"
objptr_offset, vptr_offset, vtable_offset = "<<<objptr_offset>>>", <<<vptr_offset>>>, <<<vtable_offset>>>

import idc
import idaapi
import idautils

base = idaapi.get_imagebase()
call_addr += base
ref_objptr_addr += base
ref_vptr_addr += base
ref_vtable_addr += base

if mode == "OBJPTR":
    bp_addr = ref_objptr_addr
elif mode == "VPTR":
    bp_addr = ref_vptr_addr
elif mode == "VTABLE":
    bp_addr = ref_vtable_addr

class ReadMemoryError(Exception):
    pass

def read_dword_checked(ea):
    if ea is None:
        raise ReadMemoryError("read_dword_checked: ea is None")
    val = idc.read_dbg_dword(ea)
    if val is None:
        raise ReadMemoryError("read_dword_checked: read "+ str(ea) +" failed")
    return val

def append_cmt(ea, cmt, repeatable=0, func=False, allow_duplicate=False):
    if func:
        cur_cmt = idc.get_func_cmt(ea, repeatable)
    else:
        cur_cmt = idc.get_cmt(ea, repeatable)
    if not allow_duplicate and (cur_cmt and cmt in cur_cmt):
        return
    if cur_cmt:
        new_cmt = cur_cmt + "\n" + cmt
    else:
        new_cmt = cmt
    if func:
        idc.set_cmt(ea, new_cmt, repeatable)
    else:
        idc.set_func_cmt(ea, new_cmt, repeatable)


def is_code(ea):
    return idc.is_code(idaapi.get_flags(ea))

def is_register(offset):
    return offset[0] == "R"

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


def extract_object_name(name):
    sep_index = name.find("::")
    if sep_index != -1:
        return name[:sep_index]
    return ""


def get_fixed_name(address, prefix=""):
    name = get_name(address)
    #if (
    #    name.startswith("sub_")
    #    or name.startswith("off_")
    #    or name.startswith("loc_")
    #    or name == ""
    #):
    addr_hex = hex(address - base)[2:-1]  # idc.SegStart(int(address))
    if addr_hex[-1] == "L":
        addr_hex = addr_hex[:-1]
    name = prefix + addr_hex
    return name  # nullsub_ or already renamed


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


def get_c_struct_str(name, member_decls):
    struct = "struct " + name + " {\n"
    for member_decl in member_decls:
        struct += member_decl + ";\n"
    struct += "};\n"
    return struct


def get_decompiled_func_type(vfunc_value):
    d = idaapi.decompile(vfunc_value)
    return idaapi.cfunc_type(d).dstr()


def to_func_ptr_decl(func_type, func_name):
    ptr_str = "(*" + func_name + ")("
    return func_type.replace("(", ptr_str, 1)


def rename_function(func_addr, func_name):
    succ = idaapi.set_name(func_addr, func_name, idaapi.SN_FORCE)
    if not succ:
        raise Exception(
            "rename_function to `" + func_name + "` failed with " + hex(func_addr)
        )


def create_vtable_struct(object_struct_name, vtable_struct_name, vtable_addr):
    vfunc_offset = 0
    prefix = object_struct_name + "::vfunc_"
    fp_decls = []

    # skip initial 0x0 (somehow happens to libart.so)
    # https://alschwalm.com/blog/static/2016/12/17/reversing-c-virtual-functions/
    # This is an eccentricity of newer versions of GCC. The compiler will replace
    # the destructor entries with NULL pointers in classes that have a pure-virtual
    # method (i.e., classes that are abstract).

    while True:
        vfunc_addr = read_dword_checked(vtable_addr + vfunc_offset)
        if vfunc_addr == 0:
            vfunc_offset += 4
        else:
            break

    while True:
        vfunc_addr = read_dword_checked(vtable_addr + vfunc_offset)
        if vfunc_addr == 0 or vfunc_addr >> 24 == 0xFF:
            # TODO: use Offset to Top component (negative offset) to find the end of the vtable
            break

        vfunc_addr = sub_one_if_thumb(vfunc_addr)
        vfunc_name = get_fixed_name(vfunc_addr, prefix)
        vfunc_type = idc.get_type(vfunc_addr)
        if vfunc_type:
            # assume already renamed
            existing_obj_type = extract_object_name(vfunc_name)
            if not existing_obj_type:
                raise Exception(
                    "create_vtable_struct: extract_object_name failed with typed function:\n"
                    + vfunc_name
                )
            if object_struct_name != existing_obj_type:
                append_cmt(vfunc_addr, object_struct_name, repeatable=0, func=True)
        else:
            # assume also haven't renamed
            rename_function(vfunc_addr, get_fixed_name(vfunc_addr, prefix))
            # currently use xref and method name link is enough
            # idc.set_func_cmt(vfunc_addr, vfunc_name+" @ "+ vtable_name, 1)
            # cast vfunc
            vfunc_type = get_decompiled_func_type(vfunc_addr)
            arg_start_idx = vfunc_type.find("(") + 1
            args = vfunc_type[arg_start_idx : vfunc_type.find(")")].split(",")
            if len(args) > 0:
                args[0] = object_struct_name + " *this"
                vfunc_type = vfunc_type[:arg_start_idx] + ",".join(args) + ")"
                vfunc_decl = (
                    vfunc_type[: arg_start_idx - 1] + " f(" + ",".join(args) + ")"
                )
                #print(vfunc_decl)
                func_type_tuple = idc.parse_decl(vfunc_decl, idc.PT_SILENT)
                idc.apply_type(vfunc_addr, func_type_tuple)
        fp_decl = to_func_ptr_decl(vfunc_type, vfunc_name)
        fp_decls.append(fp_decl)
        vfunc_offset += 4  # Use 4 bytes for 32-bit

    # create c struct declaration with fp_decls
    vtable_c_struct = get_c_struct_str(vtable_struct_name, fp_decls)
    struct_id = idc.SetLocalType(-1, vtable_c_struct, 0)
    if struct_id == 0:
        raise Exception("SetLocalType failed with:\n" + vtable_c_struct)
    return struct_id


def create_and_cast_vtable(object_struct_name, vtable_struct_name, vtable_addr):
    struct_id = create_vtable_struct(
        object_struct_name, vtable_struct_name, vtable_addr
    )
    if not idc.SetType(vtable_addr, vtable_struct_name):
        raise Exception("create_and_cast_vtable: SetType failed")
    # annotate vtable
    vtable_name = get_fixed_name(vtable_addr, "vtable_")
    idaapi.set_name(vtable_addr, vtable_name, idaapi.SN_FORCE)
    append_cmt(vtable_addr, vtable_name, 1)
    return struct_id


OBJ_COUNT_FILE = "obj_count.txt"


def get_obj_count():
    with open(OBJ_COUNT_FILE, "r") as f:
        return int(f.read())


def inc_obj_count():
    with open(OBJ_COUNT_FILE, "r+") as f:
        cnt = f.read()
        f.seek(0)
        f.write(str(int(cnt) + 1))
        f.truncate()


def get_addrs():
    def get_vfunc_addr(vtable_addr, vtable_offset):
        vfunc_addr_mem = read_dword_checked(vtable_addr + vtable_offset)
        vfunc_addr = sub_one_if_thumb(vfunc_addr_mem)
        return vfunc_addr
    
    if mode == "OBJPTR":
        objptr_addr = idc.GetRegValue(objptr_register) + (idc.GetRegValue(objptr_offset) if is_register(objptr_offset) else int(objptr_offset, 16))
        object_addr = read_dword_checked(objptr_addr) + vptr_offset
        vtable_addr = read_dword_checked(object_addr)
        vfunc_addr = get_vfunc_addr(vtable_addr, vtable_offset)
        return objptr_addr, object_addr, vtable_addr, vfunc_addr
    elif mode == "VPTR":
        object_addr = idc.GetRegValue(vptr_register) + vptr_offset
        vtable_addr = read_dword_checked(object_addr)
        vfunc_addr = get_vfunc_addr(vtable_addr, vtable_offset)
        return None, object_addr, vtable_addr, vfunc_addr
    else: # "VTABLE"
        vtable_addr = idc.GetRegValue(vtable_register)
        vfunc_addr = get_vfunc_addr(vtable_addr, vtable_offset)
        return None, None, vtable_addr, vfunc_addr


def do_logic():
    objptr_addr, object_addr, vtable_addr, vfunc_addr = get_addrs()

    # v_func_addr possibly invalid
    # .text:CAEDF134 LDR.W           R2, [R5,#0x150]
    # .text:CAEDF138 CBZ             R2, loc_CAEDF146 (branch if zero)
    # .text:CAEDF13A LDR.W           R0, [R5,#0x154]
    # .text:CAEDF13E MOV             R1, R4
    # .text:CAEDF140 BLX             R2
    if not is_code(vfunc_addr):
        return

    # check whether vtable has been typed
    vtable_struct_name = idc.GetType(vtable_addr)
    if not vtable_struct_name:  # create vtable struct & object struct
        # create object name first
        # TODO: optimize object count read write
        cnt = get_obj_count()
        object_struct_name = "Obj_" + str(cnt)
        dummy_c_struct = get_c_struct_str(object_struct_name, ["void *vptr"])
        obj_struct_id = idc.SetLocalType(-1, dummy_c_struct, 0)
        # cast vtable with `object_struct_name::vtable`
        vtable_struct_name = object_struct_name + "::vtable"
        vtable_struct_id = create_and_cast_vtable(
            object_struct_name, vtable_struct_name, vtable_addr
        )
        # create object type
        object_c_struct = get_c_struct_str(
            object_struct_name, [vtable_struct_name + " *vptr"]
        )
        idc.SetLocalType(obj_struct_id, "", 0)
        obj_struct_id = idc.SetLocalType(obj_struct_id, object_c_struct, 0)
        if obj_struct_id != 0:
            inc_obj_count()
        else:
            raise Exception("SetLocalType failed with:\n" + object_c_struct)

    else:  # already typed, use existing object struct & vtable struct
        object_struct_name = extract_object_name(vtable_struct_name)
        vtable_struct_id = idc.GetStrucIdByName(vtable_struct_name)
        # obj_struct_id = idc.GetStrucIdByName(object_struct_name)
        if not object_struct_name or not object_struct_name.startswith("Obj_"):
            return
            # raise Exception(
            #    "do_logic: extract_object_name failed with:\n" + vtable_struct_name
            # )

    # annotate code
    if objptr_addr:
        existing_objptr_type = idc.GetType(objptr_addr)
        if not existing_objptr_type:
            if not idc.SetType(objptr_addr, object_struct_name + "*"):
                # print(hex(objptr_addr))
                raise Exception("SetType to objptr failed")

            pobj_name = get_fixed_name(objptr_addr, "p_" + object_struct_name.lower() + "_")
            if not idaapi.set_name(objptr_addr, pobj_name, idaapi.SN_FORCE):
                raise Exception(
                    "set_name pobj " + pobj_name + "to" + hex(objptr_addr) + " failed"
                )
        else:
            if not existing_objptr_type.startswith(object_struct_name):
                append_cmt(objptr_addr, object_struct_name + "*", repeatable=1)

    if object_addr:
        if not idc.GetType(object_addr):  # objects only have one fixed type
            if not idc.SetType(object_addr, object_struct_name):
                # print(hex(object_addr))
                raise Exception("SetType to obj failed")

            obj_name = get_fixed_name(object_addr, object_struct_name.lower() + "_")
            if not idaapi.set_name(object_addr, obj_name, idaapi.SN_FORCE):
                raise Exception(
                    "set_name obj " + obj_name + "to " + hex(object_addr) + " failed"
                )

    idc.OpStroff(idautils.DecodeInstruction(ref_vtable_addr), 1, vtable_struct_id)

    # add xref to obj & vtable (ida ignores duplicate xref and returns True)
    if object_addr and not idc.add_dref(ref_vptr_addr, object_addr, idc.XREF_USER | idc.dr_R):
        raise Exception(
            "xref failed to object at address:"
            + hex(ref_vptr_addr)
            + " to "
            + hex(object_addr)
        )
    if not idc.add_dref(
        ref_vtable_addr, vtable_addr + vtable_offset, idc.XREF_USER | idc.dr_R
    ):
        raise Exception(
            "xref failed to vtable at address:"
            + hex(ref_vptr_addr)
            + " to "
            + hex(vtable_addr)
        )

    if not idc.add_cref(call_addr, vfunc_addr, idc.XREF_USER | idc.fl_CF):
        raise Exception(
            "xref failed at call addr:" + hex(call_addr) + " to " + hex(vfunc_addr)
        )


try:
    do_logic()
    # disable after cond executed
    # print("Disabling BP at:", hex(bp_addr + base))
    idaapi.enable_bpt(bp_addr, False)
except ReadMemoryError: # comment out this to debug
    pass
except Exception as e:
    print(e)
    import traceback

    traceback.print_exc()
    # print("Error! at BP address:", hex(idc.GetRegValue("pc")))
    return True
