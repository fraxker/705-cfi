from capstool.capstool import CapsTool, BCC, END, BNC
import string

def disassemble(addr, cs: CapsTool, debug=False):
    visited = []
    addr_bcc = {}
    strings = {}
    while True:
        instr = cs.get_mnem(addr)
        if debug:
            print(hex(addr), instr , addr_bcc) # , [hex(x) for x in visited]
        if instr is None or cs.dword(addr) == 0x0:
            status, t_addr = cs.get_false_key(addr_bcc)
            if status:
                addr = t_addr
                continue
            else:
                break
        if addr in addr_bcc:
            if addr_bcc[addr] is False:
                addr_bcc[addr] = True
            else:
                status, t_addr = cs.get_false_key(addr_bcc)
                if status:
                    addr = t_addr
                    continue
                else:
                    break
        if addr not in visited:
            visited.append(addr)
        if instr in BNC:
            status, op_dist = cs.get_op_dist(64, addr)
            if status:
                addr = addr + op_dist
                if addr in visited:
                    if addr in addr_bcc:
                        if addr_bcc[addr] is False:
                            addr_bcc[addr] = True
                    else:
                        addr_bcc[addr] = False
                    status, t_addr = cs.get_false_key(addr_bcc)
                    if status:
                        addr = t_addr
                        continue
                continue
        elif instr in BCC:
            if cs.word(addr) != 0x15ff:
                status, op_dist = cs.get_op_dist(64, addr)
                if status:
                    cal_addr = addr + op_dist
                    if cal_addr not in addr_bcc:
                        if cal_addr not in visited:
                            addr_bcc[cal_addr] = False
                    if cs.byte(cal_addr - 1) == 0x00:
                        temp_data = cs.get_many_bytes(addr + 5, op_dist - 6)
                        if temp_data:
                            if all(c in string.printable for c in temp_data):
                                strings[addr] = temp_data
                                status, t_addr = cs.get_false_key(addr_bcc)
                                if status:
                                    addr = t_addr
                                    continue
        elif instr in END:
            status, t_addr = cs.get_false_key(addr_bcc)
            if status:
                addr = t_addr
                continue
            else:
                break
        addr = cs.next_head(addr)

    return visited, strings