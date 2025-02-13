Two levels of struct: Asm & C (guesssed for disasm and decompile)
https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/assembler-level-and-c-level-types

https://chatgpt.com/share/67a61f8c-37b4-8006-9a24-c5aa84bd8779

```
# construct c_struct (MyStruct) definition
idc.SetLocalType(-1, c_struct, 0)
idc.SetType(0x4165FD, "MyStruct *") # return bool
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

still normal case but with post inc

```
MOV             R5, R4
LDR.W           R0, [R5],#8 ; ; Load from R5, then R5 = R5 + 8 (not sure why)
LDR             R1, [R0,#8] ;
MOV             R0, R4 ; R4 is obj+0
BLX             R1
```

call composite object

```
.text:00083A06                 LDR.W           R2, [R0,#8]! ; R0 (this) points to obj+8, is composition
.text:00083A0A                 LDR             R2, [R2,#0x28] ;
.text:00083A0C                 VMUL.F32        S0, S0, S2
.text:00083A10                 VMOV            R1, S0
.text:00083A14                 BLX             R2
```

do something between (cannot assume consecutive)

```
.text:001F11E2                 LDR             R0, [R4]
.text:001F11E4                 LDR             R1, [R5,#0xC]
.text:001F11E6                 LDR             R2, [R0,#0x38]
.text:001F11E8                 MOV             R0, R4
.text:001F11EA                 BLX             R2
```

obj is at stack (parse & cast stack address)

```
.text:002C6102                 LDR             R0, [SP,#0x108+var_E0]
.text:002C6104                 LDR             R1, [R0,#0x28]
.text:002C6106                 MOVS            R2, #0
.text:002C6108                 STR             R1, [SP,#0x108+var_104]
.text:002C610A                 MOV             R1, R2
.text:002C610C                 LDR             R2, [SP,#0x108+var_104]
.text:002C610E                 BLX             R2
```

directly get vtable from arg? (0x104778)

call from member fp? (R4 is this)

```
LDRB             R2, [R1,#9]
ADD.W            R0, R6, #0xC
LDR.W            R12, [R4,#0x18]
ADDS             R1, R5, R0
ADDS             R3, R7, R0
MOV              R0, R4
MOV              R6, R2
STR.W            R10, [SP,#0x6E8+var_6E8]
LSLS             R2, R6, #1
STR              R1, [SP,#0x6E8+var_6BC]
STR              R3, [SP,#0x6E8+var_6B8]
BLX             R12
```

load from different reg (R10 seems obj ptr)

```
LDRH            R0, [R7]
LDR.W           R1, [R10,#4]
BLX             R1
MOV             R9, R7
MOV             R6, R0
LDRH.W          R0, [R9,#4]!
LDR.W           R1, [R10,#4]
BLX             R1
```

R0 unknown (R5 seems not vptr)

```
LDR             R0, [R5]
STR             R6, [R5]
CBZ             R0, loc_3C316
LDR             R1, [R5,#4]
BLX             R1
```

TODO: handle `!` & `[], #off` & no obj case , distinguish fptr call and virtual call
always use value in []

Mode Syntax Behavior
Offset Addressing LDR R0, [R1, #8] Load from R1 + 8, R1 unchanged
Pre-Indexed LDR R0, [R1, #8]! Update R1 = R1 + 8, then load
Post-Indexed LDR R0, [R1], #8 Load first, then R1 = R1 + 8
Register Offset LDR R0, [R1, R2] Load from R1 + R2
Register Offset with Shift LDR R0, [R1, R2, LSL #n] Load from R1 + (R2 << n)
Pre-Indexed with Register Offset LDR R0, [R1, R2]! R1 = R1 + R2, then load
Post-Indexed with Register Offset LDR R0, [R1], R2 Load first, then R1 = R1 + R2
Literal Addressing LDR R0, =value Load a value using PC-relative addressing

idc.GetType: return type only at exact position
