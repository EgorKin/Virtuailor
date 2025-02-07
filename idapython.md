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

call every module's functions through idaapi

```
from ida_allins import *
from ida_range import *
from ida_auto import *
from ida_bytes import *
from ida_dbg import *
from ida_diskio import *
from ida_entry import *
from ida_enum import *
from ida_expr import *
from ida_fixup import *
from ida_fpro import *
from ida_frame import *
from ida_funcs import *
from ida_gdl import *
from ida_graph import *
from ida_hexrays import *
from ida_ida import *
from ida_idaapi import *
from ida_idd import *
from ida_idp import *
from ida_kernwin import *
from ida_lines import *
from ida_loader import *
from ida_moves import *
from ida_nalt import *
from ida_name import *
from ida_netnode import *
from ida_offset import *
from ida_pro import *
from ida_problems import *
from ida_registry import *
from ida_search import *
from ida_segment import *
from ida_segregs import *
from ida_strlist import *
from ida_struct import *
from ida_typeinf import *
from ida_tryblks import *
from ida_ua import *
from ida_xref import *
from ida_idc import *
```
