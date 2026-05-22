from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

def get_symbol_at_address(elffile, target_address):
    for section in elffile.iter_sections():
        if section.header['sh_type'] in ('SHT_RELA', 'SHT_REL'):
            for relocation in section.iter_relocations():
                if relocation['r_offset'] == target_address:
                    symtab = elffile.get_section(section.header['sh_link'])
                    symbol = symtab.get_symbol(relocation['r_info_sym'])
                    return symbol.name
                    
    dynsym = elffile.get_section('.dynsym')
    if dynsym:
        for symbol in dynsym.iter_symbols():
            if symbol.entry['st_value'] == target_address:
                return symbol.name
                
    return None

def calculate_target(insn):
    if len(insn.operands) > 0:
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                return op.imm
            elif op.type == CS_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    return insn.address + insn.size + op.mem.disp
                elif op.mem.base == X86_REG_INVALID and op.mem.index == X86_REG_INVALID:
                    return op.mem.disp
    return None

def read_string_at_vaddr(elffile, vaddr):
    """
    finds the segment containing the virtual address and reads characters until it hits a null terminator.
    """
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            seg_start = segment.header.p_vaddr
            seg_end = seg_start + segment.header.p_memsz
            
            if seg_start <= vaddr < seg_end:
                data = segment.data()
                offset = vaddr - seg_start
                
                string_bytes = bytearray()
                while offset < len(data):
                    char_byte = data[offset]
                    if char_byte == 0: # null term
                        break
                    string_bytes.append(char_byte)
                    offset += 1
                    
                return string_bytes.decode('utf-8', errors='replace')
    return None

if __name__ == "__main__":
    f = open("main", "rb")
    elffile = ELFFile(f)

    entry_point = elffile.header.e_entry
    print(f"Entry point address: {hex(entry_point)}")
    print(f"Object file type: {elffile.header.e_type}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)    
    md.detail = True

    target_segment = None
    for segment in elffile.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            vaddr = segment['p_vaddr']
            memsz = segment['p_memsz']
            
            if vaddr <= entry_point < (vaddr + memsz):
                target_segment = segment
                break

    if not target_segment:
        print("could not find segment containing entry point")
        exit()

    segment_data = target_segment.data()
    seg_start = target_segment.header.p_vaddr
    seg_end = seg_start + target_segment.header.p_memsz

    worklist = [entry_point]
    visited_blocks = set()

    register_state = {"rdi": None}

    while worklist:
        current_address = worklist.pop(0)
        if current_address in visited_blocks:
            continue

        visited_blocks.add(current_address)

        if not (seg_start <= current_address < seg_end):
            sym_name = get_symbol_at_address(elffile, current_address)
            print(f"[external reference] {hex(current_address)} -> {sym_name if sym_name else 'Unknown'}")

            if sym_name == "__libc_start_main" and register_state["rdi"] is not None:
                discovered_main = register_state["rdi"]
                print(f"automatically discovered 'main' at: {hex(discovered_main)}")
                worklist.append(discovered_main)
            if sym_name == "printf" and register_state["rdi"] is not None:
                fmt_string = read_string_at_vaddr(elffile, register_state["rdi"])
                print(f"printf rdi: {hex(register_state["rdi"])}, fmtstr: {fmt_string.encode("utf-8")}")

            continue

        offset = current_address - target_segment.header.p_vaddr
        code_bytes = segment_data[offset : offset + 256]

        if not code_bytes:
            break
            
        instructions = list(md.disasm(code_bytes, current_address))    

        if not instructions:
            break

        print(f"--- disassembling block at {hex(current_address)} ---")
        for insn in instructions:
            print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            
            if insn.mnemonic in ["lea", "mov"] and insn.op_str.startswith("rdi,"):
                target = calculate_target(insn)
                if target:
                    register_state["rdi"] = target

            if insn.mnemonic == "jmp":
                target = calculate_target(insn)
                if target:
                    worklist.append(target)
                break
            elif insn.mnemonic.startswith("j"):
                target = calculate_target(insn)
                if target:
                    worklist.append(target)
                fallthrough = insn.address + insn.size
                worklist.append(fallthrough)
                break
            elif insn.mnemonic == "call":
                target = calculate_target(insn)
                if target:
                    worklist.append(target)
            elif insn.mnemonic in ["ret", "hlt"]:
                break

    """for seg in elffile.iter_segments():
        print(f"Type: {seg.header.p_type}\nOffset: {hex(seg.header.p_offset)}\nVirtual address: {hex(seg.header.p_vaddr)}\nPhysical address: {hex(seg.header.p_paddr)}\nSize in file: {hex(seg.header.p_filesz)}\nSize in memory: {hex(seg.header.p_memsz)}")

        print("Sections:")
        for sec in elffile.iter_sections():
            if seg.section_in_segment(sec):
                print(f"{sec.name}, offset: {hex(sec.header.sh_offset)}, size: {hex(sec.header.sh_size)}")

        print("---")
    """

