from avatar_common import PSPEmulator

# Only required when enabling qemu tracing
# TRACE_PARSE = 'avatar2/targets/src/avatar-qemu/scripts/simpletrace.py'
# TRACE_FILE = 'avatar2/targets/build/qemu/trace-events-all'
# QEMU_ARGS = ["-singlestep", "-trace", "file=/tmp/trace", "-monitor", "telnet:127.0.0.1:4444,server,nowait"]

QEMU_ARGS = ["-monitor", "telnet:127.0.0.1:4444,server,nowait"]
QEMU_BIN = "path_to_avatar_qemu"
BINARY = "path_to_extracted_bl"


psp = PSPEmulator()

# Entry address. To print mem accesses set "verbose = True"
psp.init(0x100, QEMU_BIN, QEMU_ARGS, interactive=False)
# Load bl file into memory: mem_offset, mem_size, binary, file_offset, file_size
# The demo presented at ccc camp used an Epyc bootloader ver. 0.7.0.52 
psp.load_file(0x0, 0xd000, BINARY, TODO, 0xd000)


# 1 Page of virtual CCP
psp.add_virtual_ccp(0x03001000)

# 1 Page of virtual Timer
psp.add_virtual_timer(0x03010000)

# 1 Stack Page This page is later mapped at 0x51000, the SVC SP is set to 0x52000
psp.add_memory_range(0x0003d000, 0x3f000)

# Userspace app memory range
psp.add_memory_range(0x15000, 0x16000)

# 2 Pages for PTABLE
psp.add_memory_range(0x00013000, 0x15000)

# Required to allow emulation to continue
psp.set_memory_value(0x3fa55, 1, size=1)
psp.set_memory_value(0x3fa53, 1, size=1)
psp.set_memory_value(0x3fa60, 0xFF, size=1)
psp.set_memory_value(0x03010104, 0x80002)
psp.set_memory_value(0x26d81e77, 0xFF, size=1)
psp.set_memory_value(0x240003fd, 0xFF, size=1)

psp.qemu_init()

# We don't want to end up here (endless loops)
psp.set_breakpoint(0xf56)
psp.set_breakpoint(0xfe4)
psp.set_breakpoint(0x1126)
psp.set_breakpoint(0x1154)
psp.set_breakpoint(0x1160)
psp.set_breakpoint(0x1182)
psp.set_breakpoint(0x11f0)
psp.set_breakpoint(0x1202)

# Main init function
psp.set_breakpoint(0xf18)

psp.run()
