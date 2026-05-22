from elftools.elf.elffile import ELFFile

if __name__ == "__main__":
    elffile = ELFFile(open("main", "rb"))

    entry_point = elffile.header.e_entry
    print(f"Entry point address: {hex(entry_point)}")

    for seg in elffile.iter_segments():
        print(f"Type: {seg.header.p_type}\nOffset: {hex(seg.header.p_offset)}\nVirtual address: {hex(seg.header.p_vaddr)}\nPhysical address: {hex(seg.header.p_paddr)}\nSize in file: {hex(seg.header.p_filesz)}\nSize in memory: {hex(seg.header.p_memsz)}")

        print("Sections:")
        for sec in elffile.iter_sections():
            if seg.section_in_segment(sec):
                print(f"{sec.name}, offset: {hex(sec.header.sh_offset)}, size: {hex(sec.header.sh_size)}")

        print("---")

