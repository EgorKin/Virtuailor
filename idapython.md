Two levels of struct: Asm & C (guesssed for disasm and decompile)
https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/assembler-level-and-c-level-types

https://chatgpt.com/share/67a61f8c-37b4-8006-9a24-c5aa84bd8779

```
# construct c_struct (MyStruct) definition
idc.SetLocalType(-1, c_struct, idc.LTF_STRUCT)
idc.SetType(0x4165FD, "MyStruct *")
```

Get function type:

```
t= ida_typeinf.tinfo_t(); idaapi.decompile(0x285460).get_func_type(t)
# or t = idaapi.cfunc_type(idaapi.decompile(0x285460))
# seems must go through decompile, even though only need type, which may depends on function's content
t.dstr()
# add (*) before ( and SetType
# can change to __thiscall, any arg type, name ok
```

call every module's functions through idaapi (import \* from almost all (except idc) modules)

arm only has one calling convention (ARM Calling Convention), so **fastcall, **thiscall are all the same.
Arguments: R0–R3. (stack the rest)
Callee-saved registers: R4-R11 must be preserved by the function.
Caller-saved registers: R0-R3, R12 can be freely modified.
