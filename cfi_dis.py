from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstool.capstool import CapsTool
import lief
from pathlib import Path
from rec_dis import disassemble
lief.logging.disable()

def get_disasm_ex(data, ea, md: Cs):
    """
    Get disassembly line
    @param ea: linear address of instruction
    @param flags: combination of the GENDSM_ flags, or 0
    @return: "" - could not decode instruction at the specified location
    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    code = data[ea:ea + 15]
    for i in md.disasm_lite(code, ea):
        return i
    else:
        return None

def getBaseAddress(binary):
    elffile = lief.parse(binary)
    # Determine base address of binary
    #
    base_addr = 0
    candidates = [0xFFFFFFFFFFFFFFFF]
    for section in elffile.sections:
        if section.virtual_address:
            candidates.append(section.virtual_address - section.offset)
    if len(candidates) > 1:
        base_addr = min(candidates)
    return base_addr

if __name__ == "__main__":
    file = Path("/bin/ssh")
    file_bytes = file.read_bytes()
    base = getBaseAddress(file_bytes)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Linear Dissasmbly
    inst = list(md.disasm_lite(file_bytes, base))
    total_size = sum([x[1] for x in inst])
    print(f"Linear Disassembly instructions: {inst}")
    print(f"Linear Disassembly byte count: {total_size}")

    # Recusrsive disassembly
    size = 0
    cs = CapsTool(file_bytes, 64)
    yy, _ = disassemble(0, cs)
    inst_rec = list([get_disasm_ex(file_bytes, x, md) for x in yy])
    size = sum([x[1] for x in inst_rec])
    print(f"Recursive Disassembly instructions: {inst_rec}")
    print(f"Recursive Disassembly byte count: {size}")