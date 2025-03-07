import ida_kernwin
import idaapi
import idc


def apply_patch():

    dif_path = ida_kernwin.ask_file(0, "*.dif", "Select dif file")
    with open(dif_path, "r") as f:
        lines = f.readlines()

    # patches = []
    for line in lines[3:]:
        elems = line.strip().split(" ")
        addr = int(elems[0][:-1], 16)
        pb = int(elems[2], 16)
        idc.patch_byte(addr, pb)
        # patches.append((addr, pb))

    # start_addr, length = patches[0][0], 0
    # for addr, pb in patches:
