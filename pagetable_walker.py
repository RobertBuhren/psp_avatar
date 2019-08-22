#!/usr/bin/env python
import sys
import struct

# ARMv7 supports two different paging formats: short & long. TTBCR.EAE defines
# which format is currently active.
# The Epyc PSP BL sets TTBCR to 0x22 at 0x15c
# 0x22 = 0b100010: TTBCR.N = 0b010 TTBCR.PD1 = 1 TTBCR.PD0 = 0
# This BL uses TTBR0 with an N value of 2

N = 2

# First level is indexed with bits VA[31-N:20]
FIRST_LEVEL_INDEX_MASK = ((((1 << (32-N-20)) - 1) << 20))

# Second level is indexed with bits VA[19:12]
SECOND_LEVEL_INDEX_MASK = (((1 << 8) - 1) << 12)

# PT base adrress is determined by bits [31:10]
PAGETABLE_BASE_MASK = ((( 1 << 32-10) -1) << 10)

# Filename of the dumped binary
FILENAME = sys.argv[1]

# This is the value of the TTBR0
PT_BASE_ADDR = 0x14000

# If the short format is used, only bits > 14 -N from TTBR0 are used.
PT_BASE_ADDR &= (((1 << (32-(14-N))) - 1) << (14-N))

# This is the offset of the TTBR0 within the dumped binary
TTBR_FILE_OFFSET = 0x1000

ignored = 0
last_section = 0
last_ptentry = 0
last_ignored = 0


def print_section(addr, entry):
    phys = entry & (((1 << 12) - 1) << 20)
    xn = (entry & (1 << 4)) >> 4
    b = (entry & (1 << 2)) >> 2
    c = (entry & (1 << 3)) >> 3
    px = entry & 0x1
    tex = (entry & (((1 << 3) - 1) << 12)) >> 12
    mem_type = "UNKNOWN"
    caching = (tex << 2) | (c << 1) | b
    if caching == 0b01000:
        mem_type = "device"
    elif caching == 0b00100:
        mem_type = "normal"
    elif caching == 0b00111:
        mem_type = "normal"
    elif caching == 0b10011:
        mem_type = "normal"

    ap1 = (entry & (((1 << 2) - 1) << 10)) >> 10
    ap2 = (entry & (1 << 15)) >> 15
    ns = (entry & (1 << 19)) >> 19
    print("Section: Virt %08x : Phys %08x. XN: %x PXN: %x ns: %x tex: %05s ap: %05s b: %x c: %x raw: %08x mem_type: %s" %
          (addr, phys, xn, px, ns, bin(tex),  bin(ap1 | (ap2 << 2)), b, c, entry, mem_type))


def print_ptentry(addr, entry, px, ns):
    if (entry & 0b11) == 0b01:
        print("LARGEPAGE")
    elif (entry & 0b10):
        phys = entry & 0xfffff000
        xn = entry & 0b1
        b = (entry & (1 << 2)) >> 2
        c = (entry & (1 << 3)) >> 3
        tex = (entry & ((1 << 3) - 1 << 6)) >> 6
        ap1 = (entry & ((1 << 2) - 1 << 4)) >> 4
        ap2 = (entry & (1 << 9)) >> 9
        mem_type = "UNKNOWN"
        caching = (tex << 2) | (c << 1) | b
        if caching == 0b01000:
            mem_type = "device"
        elif caching == 0b00100:
            mem_type = "normal"
        elif caching == 0b00111:
            mem_type = "normal"
        elif caching == 0b10011:
            mem_type = "normal"
        print("ptentry: Virt %08x : Phys %08x. XN: %x PXN: %x tex: %05s ap: %05s b: %x c: %x  ns: %x raw: %08x mem_type: %s" %
                (addr, phys, xn, px, bin(tex), bin(ap1 | (ap2 << 2)), b, c,ns, entry, mem_type))
    else:
        print("Not mapped")

print("HARDCODED CONSTANTS: TTBR0: 0x%x TTBR_FILE_OFFSET: 0x%x" % 
        (PT_BASE_ADDR, TTBR_FILE_OFFSET))
print("Assuming AP[2:0] access permission control\n")

with open(FILENAME, "rb") as f:
        pagetable = f.read()

# If TTBRC.N == 2 we only translate addresses < 0xc0000000


show_exec_only = True
# for addr in range(0x0, 0xc0000000, 4096):
vaddr_start = 0x0
vaddr_end = 0xc0000000

if (len(sys.argv) == 3):
    vaddr_start = int(sys.argv[2],16)
    vaddr_end = vaddr_start+4096

# print(hex(vaddr_start))
# print(hex(vaddr_end))

addr = 0
while addr < 0xc0000000:

    first_index = (addr & FIRST_LEVEL_INDEX_MASK) >> 20
    first_level_entry = struct.unpack('<I', pagetable[(first_index*4)+TTBR_FILE_OFFSET:(first_index*4)+4+TTBR_FILE_OFFSET])
    # print("%x" % first_index)
    # print("%x" % first_level_entry)
    # print(hex(first_level_entry[0]))

    if (first_level_entry[0] & 0b11) == 0b01:
        # print("Entry is PT")
        second_index = ((addr & SECOND_LEVEL_INDEX_MASK) >> 12)
        # print("%x" % second_index)
        pagetable_file_offset = (((first_level_entry[0] & PAGETABLE_BASE_MASK) 
            - PT_BASE_ADDR) + TTBR_FILE_OFFSET)
        ptable_offset = pagetable_file_offset + second_index*4

        ptable_entry = struct.unpack('<I', pagetable[ptable_offset:ptable_offset+4])
        px = (first_level_entry[0] & (1 << 2)) >> 2
        ns = (first_level_entry[0] & (1 << 3)) >> 3

        print_ptentry(addr,ptable_entry[0],px,ns)
        addr += 4096


        # last_ptentry = ptable_entry[0]
    elif (first_level_entry[0] & 0b10) and (first_level_entry[0] & (1 << 18)):
        print("SUPERSECTION")
    elif (first_level_entry[0] & 0b10) and (first_level_entry[0] & ~(1 << 18)):
        print_section(addr, first_level_entry[0])
        addr += 0x01000000
    elif (first_level_entry[0] & 0b11) == 0b11:
        # print("INVALID")
        addr += 4096
    elif (first_level_entry[0] & 0b11) == 0b00:
        # print("Ignored")
        addr += 4096
    else:
        print("WTF")

