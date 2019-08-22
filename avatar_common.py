from avatar2.peripherals import AvatarPeripheral
from avatar2 import Avatar
from avatar2 import QemuTarget
from avatar2 import TargetStates
from IPython import embed
import ccp_parse

from avatar2 import RemoteMemoryReadMessage
import os
import struct

# Config:


AVATAR_DIR = '/tmp/avatar'


class PSPEmulator():

    custom_memory = bytearray(2**32)

    accessed_mem = {}

    verbose = True

    interactive = False

    ccp_cmd = {
        "process": False,
        "start": 0x0,
        "end": 0x0
    }
    qemu = None

    def __init__(self):
        self.avatar = None
        self.close = False
        self.trace_parse = None
        self.trace_file = None
        self.ignored_addresses = set()

    def init(self, entry_addr, qemu_bin, qemu_args, verbose=False,
             interactive=False):
        self.avatar = Avatar(output_directory=AVATAR_DIR)
        self.avatar.log.setLevel('DEBUG')

        PSPEmulator.verbose = verbose
        PSPEmulator.interactive = interactive

        PSPEmulator.qemu = self.avatar.add_target(QemuTarget, name='qemu1',
                                                  executable=qemu_bin,
                                                  gdb_executable="arm-eabi-gdb",
                                                  additional_args=qemu_args)
        PSPEmulator.qemu.cpu_model = 'cortex-a8'

        self.avatar.watchmen.add_watchman('RemoteMemoryRead', 'before',
                                          self.before_remote_memory_access,
                                          is_async=False)
        self.avatar.watchmen.add_watchman('RemoteMemoryWrite', 'before',
                                          self.before_remote_memory_access,
                                          is_async=False)

        PSPEmulator.qemu.entry_address = entry_addr

    def load_file(self, address, mem_size, filename, offset, file_size):
        self.avatar.add_memory_range(address, mem_size, file=filename,
                                     file_offset=offset, file_bytes=file_size)

    def load_custom_mem(self, address, filename, offset=0, size=0):
        f = open(filename, 'rb')
        if offset != 0:
            f.seek(offset)

        if size != 0:
            data = f.read(size)
        else:
            data = f.read()

        self.custom_memory[address:address+len(data)] = data

    def add_memory_range(self, start, end, permissions='rw-'):
        if ((end-start) % 0x1000) != 0:
            print("[PSPEmulator] ERROR: memory ranges must be page aligned"
                  "(0x%.8x)" % start)
        self.avatar.add_memory_range(start, end-start, permission=permissions)

    def set_memory_value(self, address, value, size=4):
        if size != 1 and size != 4:
            print("[PSPEmulator] ERROR: Only 1 or 4 bytes are supported")
            return

        if size == 1:
            PSPEmulator.custom_memory[address] = value
        elif size == 4:
            bval = (value).to_bytes(4, byteorder='big')
            PSPEmulator.custom_memory[address] = bval[0]
            PSPEmulator.custom_memory[address+1] = bval[1]
            PSPEmulator.custom_memory[address+2] = bval[2]
            PSPEmulator.custom_memory[address+3] = bval[3]

    def qemu_init(self):
        PSPEmulator.qemu.init()

    def set_breakpoint(self, address):
        PSPEmulator.qemu.set_breakpoint(address)

    def watch_memory_range(self, start, end, permissions='rw-'):
        if ((end-start) % 0x1000) != 0:
            print("[PSPEmulator] ERROR: watched memory ranges must be page"
                  "aligned (0x%.8x)" % start)
            return
        self.avatar.add_memory_range(start, end-start,
                                     emulate=CustomMemoryPeripheral,
                                     permission=permissions)

    def add_virtual_ccp(self, address):
        if not PSPEmulator.qemu:
            print("[PSPEmulator] ERROR: PSPEmulator not initialized yet. Call"
                  "init() first")
            return
        self.avatar.add_memory_range(address, 0x1000, emulate=VirtualCCP,
                                     permission='rw-')
        # self.ignored_addresses.add(address)

    def add_misc_dev(self, address):
        if not PSPEmulator.qemu:
            print("[PSPEmulator] ERROR: PSPEmulator not initialized yet. Call"
                  "init() first")
            return
        self.avatar.add_memory_range(address, 0x1000, emulate=VirtMisc,
                                     permission='rw-')

    def add_virtual_timer(self, address):
        if not PSPEmulator.qemu:
            print("[PSPEmulator] ERROR: PSPEmulator not initialized yet. Call"
                  "init() first")
            return
        self.avatar.add_memory_range(address, 0x1000, name="VirtualTimer",
                                     emulate=VirtualTimer, permission='rw-')
        # self.ignored_addresses.add(address)

    def watch_memory(self, address=None, size=None):
        # TODO: Automatically configure "remaining", i.e. not yet configured
        #       memory ranges to be backed by our CustomMemoryPeripheral
        print(self.avatar.memory_ranges)
        for interval in self.avatar.memory_ranges:
            print("0x%x 0x%x" % (interval.begin, interval.end))

    def __del__(self):
        self.avatar.shutdown()
        if self.trace_file and self.trace_parse:
            command = 'python2.7 %s %s /tmp/trace > /tmp/parsed' % \
                      (self.trace_parse, self.trace_file)
            print("[PSPEmulator] Calling %s" % command)
            os.system(command)

    def exit(self):
        self.close = True
        self.__del__()

    def disconnect_gdb(self):
        PSPEmulator.qemu.gdb.remote_disconnect()

    def connect_gdb(self):
        PSPEmulator.qemu.gdb.remote_connect()

    def run(self):
        while not self.close:
            if PSPEmulator.qemu.state != TargetStates.EXITED:
                PSPEmulator.qemu.cont()
            PSPEmulator.qemu.wait(TargetStates.EXITED | TargetStates.STOPPED)
            if PSPEmulator.qemu.state == TargetStates.STOPPED:
                if PSPEmulator.ccp_cmd["process"] is True:
                    print("[ccp_dev] Parsing new cmd at pc=0x%.8x" %
                          PSPEmulator.qemu.read_register("pc"))
                    self.print_ccp_cmds(PSPEmulator.ccp_cmd["start"],
                                        PSPEmulator.ccp_cmd["end"])
                    PSPEmulator.ccp_cmd["process"] = False
                else:
                    embed(banner1="QEMU entered STOPPED state at pc=0x%.8x" %
                          PSPEmulator.qemu.read_register("pc"))
            else:
                print("[PSPEmulator] Qemu exited with state: %s" %
                      str(PSPEmulator.qemu.state))
                self.exit()

    def print_ccp_cmds(self, start, end):

        cmds = (end - start) // 0x20
        for e in range(0x0, cmds):
            dwords = [PSPEmulator.qemu.read_memory(i, 0x4) for i in
                      range(start+(e*0x20), start+(e*0x20)+0x20, 0x4)]
            print("\n[ccp_dev] Processing ccp cmd %d" % e)
            cmt, engine = ccp_parse.parse_dword0(dwords[0])
            print("[ccp_dev]\t %s" % cmt)
            print("[ccp_dev]\t Length of src data 0x%x" % dwords[1])
            print("[ccp_dev]\t Src ptr 0x%x" % dwords[2])
            print("[ccp_dev]\t %s" % ccp_parse.parse_dword3(dwords[3]))
            print("[ccp_dev]\t %s" % ccp_parse.parse_dword4(engine, dwords[4]))
            print("[ccp_dev]\t %s" % ccp_parse.parse_dword5(engine, dwords[5]))
            print("[ccp_dev]\t Low 32bit key ptr: 0x%x" % dwords[6])
            print("[ccp_dev]\t High 16bit key ptr + mem type: 0x%x" %
                  dwords[7])
            print()

    def swap32(i):
        return struct.unpack("<I", struct.pack(">I", i))[0]

    def enable_tracing(self, trace_parse, trace_file):
        self.trace_file = trace_file
        self.trace_parse = trace_parse
        PSPEmulator.qemu.qmp.execute_command('trace-event-set-state', {'name':
                                             'exec_tb', 'enable': True})
        PSPEmulator.qemu.qmp.execute_command('trace-event-set-state', {'name':
                                             'guest_mem_before_exec', 'enable':
                                                                       True})

    def before_remote_memory_access(self, avatar, remote_memory_msg, **kwargs):
        address = remote_memory_msg.address
        pc = remote_memory_msg.pc

        # Ignore pages belonging to emulated devices
        if (address & 0xFFFFF000) in self.ignored_addresses:
            return

        read_or_write = ''
        if isinstance(remote_memory_msg, RemoteMemoryReadMessage):
            read_or_write = 'read'
        else:  # if isinstance(remote_memory_msg, RemoteMemoryWriteMessage):
            read_or_write = 'write'

        # if not PSPEmulator.ccp_cmd["process"]:
        #     print('[custom_memory] New %s at 0x%.8x from PC: 0x%.8x' % (read_or_write, address, pc))

        if address not in PSPEmulator.accessed_mem:
            PSPEmulator.accessed_mem[address] = set()

        # print("BeforeMemaccess: pc 0x%.8x addr 0x%.8x" % (pc, address))

        PSPEmulator.accessed_mem[address].add((pc, read_or_write))

    def print_custom_memory(self):
        for i in PSPEmulator.accessed_mem:
            val = int.from_bytes(PSPEmulator.custom_memory[i:i+4], 'little')
            print('\t0x%.8x: \t0x%.8x \taccessed_by: %s' %
                  (i, val, repr([v[1] + ':' + hex(v[0]) for v in PSPEmulator.accessed_mem[i]])))


class VirtMisc(AvatarPeripheral):
    ''' Unknown device '''

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        print("[%s] Initialized device at 0x%.8x (size: 0x%.0x)" %
              (name, address, size))

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

        # Unknown reg, code sets bit 0x1000 and expects that it is cleared
        self.regs = {
                0x0: 0x0
        }

    def check_access(self, offset, size):
        address = self.address + offset
        result = True
        if offset not in self.regs.keys():
            result = False
        if size != 0x4:
            print("[%s] ERROR, unaligned access to register: 0x%.8x (size: 0x%.8x)"
                  % (self.name, address, size))
        return result

    def hw_read(self, offset, size):
        address = self.address + offset 
        if self.check_access(offset, size):
            if offset == 0x0:
                self.regs[offset] &= ~0x10000
            value = self.regs[offset]
            if PSPEmulator.verbose:
                print("[%s] Read from 0x%.8x. Value 0x%.8x" %
                      (self.name, address, value))
        else:
            value = CustomMemoryPeripheral.handle_read(self.address, offset, size)
        return value

    def hw_write(self, offset, size, value):
        address = self.address + offset
        if self.check_access(offset, size) and PSPEmulator.verbose:
            print("[%s] Write to 0x%.8x. Value 0x%.8x" %
                  (self.name, address, value))
            self.regs[offset] = value
        else:
            CustomMemoryPeripheral.handle_write(self.address, offset, size, value)
        return True

class VirtualTimer(AvatarPeripheral):
    ''' Emulation of PSP Timer Device '''

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        print("[%s] Initialized device at 0x%.8x (size: 0x%.0x)" %
              (name, address, size))

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

        self.regs = {
            0x444: 0x0
        }

    def check_access(self, offset, size):
        address = self.address + offset
        result = True
        if offset not in self.regs.keys():
            result = False
        if size != 0x4:
            print("[%s] ERROR, unaligned access to register: 0x%.8x (size: 0x%.8x)"
                  % (self.name, address, size))
        return result

    def hw_read(self, offset, size):
        address = self.address + offset
        if self.check_access(offset, size):
            if offset == 0x444:
                self.regs[offset] += 0x1000
            value = self.regs[offset]
            print("[%s] Read from 0x%.8x. Value 0x%.8x" %
                  (self.name, address, value))
        else:
            value = CustomMemoryPeripheral.handle_read(self.address, offset, size)
        return value

    def hw_write(self, offset, size, value):
        address = self.address + offset
        if self.check_access(offset, size):
            print("[%s] Write to 0x%.8x. Value 0x%.8x" %
                  (self.name, address, value))
            self.regs[offset] = value
        else:
            CustomMemoryPeripheral.handle_write(self.address, offset, size, value)
        return True


class VirtualCCP(AvatarPeripheral):
    ''' Emulation of PSP CCP Device '''

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)

        print("[ccp_dev] Initialized virtual CCP dev at 0x%.8x (size: 0x%.8x)" %
              (address, size))

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

        self.regs = {
            0: 0x2,
            4: 0x0,
            8: 0x0
        }

    def process_ccp_cmds(self, start, end):
        if ((end - start) % 0x20) != 0x0:
            print("[ccp_dev] ERROR, unknown command length")
            return
        if not PSPEmulator.interactive:
            PSPEmulator.ccp_cmd["process"] = True
            PSPEmulator.ccp_cmd["start"] = start
            PSPEmulator.ccp_cmd["end"] = end
            PSPEmulator.qemu.stop(blocking=False)

    def check_access(self, offset, size):
        address = self.address + offset
        result = True
        if offset not in self.regs.keys():
            print("[ccp_dev] ERROR, access to undefined register: 0x%.8x" % address)
            result = False
        if size != 0x4:
            print("[ccp_dev] ERROR, unaligned access to register: 0x%.8x (size: 0x%.8x" % (address, size))
            result = False
        return result

    def hw_read(self, offset, size):
        if self.check_access(offset, size):
            print("[ccp_dev] Read at 0x%.8x. Value: 0x%.8x" % (self.address+offset, self.regs[offset]))
            return self.regs[offset]
        else:
            return 0

    def hw_write(self, offset, size, value):
        if self.check_access(offset, size):
            print("[ccp_dev] Write at 0x%.8x. Value: 0x%.8x" % (self.address+offset, value))
            self.regs[offset] = value

            if (self.regs[4] > self.regs[8]):
                # Only process cmds if 'ready' bit is set
                if self.regs[0] & 0x1:
                    self.process_ccp_cmds(self.regs[8], self.regs[4])
                    # reset to initial value
                    self.regs[0] = 0x2
                    self.regs[8] = self.regs[4]
                else:
                    print("[ccp_dev] Prepared ccp operation. Start: 0x%.8x End: 0x%.8x" % (self.regs[8], self.regs[4]))
            elif (self.regs[8] < self.regs[4]):
                print("[ccp_dev] ERROR, weird state: Start < End: 0x%.8x < \
                      0x%.8x" % (self.regs[8], self.regs[4]))
        return True


class CustomMemoryPeripheral(AvatarPeripheral):

    def handle_read(base, offset, size):
        if size != 1 and size != 4 and size != 2:
            embed(banner1="Weird size: %x" % size)

        address = base + offset
        if size == 1:
            value = PSPEmulator.custom_memory[address]
        elif size == 4:
            value = int.from_bytes(PSPEmulator.custom_memory[address:address+4]
                                   , 'little')
        elif size == 2:
            value = int.from_bytes(PSPEmulator.custom_memory[address:address+2]
                                   , 'little')

        if not PSPEmulator.ccp_cmd["process"] and \
                PSPEmulator.qemu.state == TargetStates.RUNNING \
                and PSPEmulator.verbose:
            print('\t[custom_memory] Returning 0x%.8x bytes from 0x%.8x (value: 0x%.8x)\n' %
                  (size, address, value))
        return value

    def handle_write(base, offset, size, value):
        if size != 1 and size != 4 and size != 2:
            embed(banner1="Weird size: %x" % size)
        address = base + offset
        if PSPEmulator.qemu.state == TargetStates.RUNNING and \
                PSPEmulator.verbose:
            print('\t[custom_memory] Write at 0x%.8x of 0x%.8x bytes (value: 0x%.8x)\n' % (address, size, value))
        if size == 1:
            PSPEmulator.custom_memory[address] = value
        elif size == 4:
            bval = (value).to_bytes(size, byteorder='little')
            for i in range(0, size):
                PSPEmulator.custom_memory[address+i] = bval[i]
        elif size == 2:
            bval = (value).to_bytes(size, byteorder='little')
            for i in range(0, size):
                PSPEmulator.custom_memory[address+i] = bval[i]

        return True

    def hw_read(self, offset, size):
        return CustomMemoryPeripheral.handle_read(self.address, offset, size)

    def hw_write(self, offset, size, value):
        CustomMemoryPeripheral.handle_write(self.address, offset, size, value)
        return True

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)

        print("[custom_memory] Initialized %s with address: 0x%.8x and size: 0x%.8x\n" %
              (name, address, size))

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
