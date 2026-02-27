#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ELF Analyzer & ROP Gadget Extractor
A lightweight, dependency-minimal binary analysis tool for CTF & Security Research.
"""

import argparse
import sys
from typing import List, Tuple, Dict
from pwn import ELF
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# --- ANSI Terminal Colors ---
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class ELFAnalyzer:
    def __init__(self, filepath: str, max_gadget_bytes: int = 16, max_insn: int = 6):
        try:
            self.elf = ELF(filepath, checksec=False)
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load ELF file: {e}{Colors.RESET}")
            sys.exit(1)
            
        self.filepath = filepath
        self.max_bytes = max_gadget_bytes
        self.max_insn = max_insn
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = False

    def check_security_mitigations(self):
        """ (Checksec)"""
        print(f"\n{Colors.CYAN}[*] Security Mitigations for {self.filepath}:{Colors.RESET}")
        
        mitigations: Dict[str, bool] = {
            "PIE": self.elf.pie,
            "NX": self.elf.nx,
            "Canary": self.elf.canary,
            "RelRO": "Full" in self.elf.relro if isinstance(self.elf.relro, str) else self.elf.relro
        }

        for name, status in mitigations.items():
            if status:
                print(f"  [+] {name:<10}: {Colors.GREEN}Enabled{Colors.RESET}")
            else:
                print(f"  [-] {name:<10}: {Colors.RED}Disabled{Colors.RESET}")

    def _get_executable_segments(self) -> List[Tuple[int, bytes]]:
        """"""
        segments = []
        for seg in self.elf.segments:
            # p_type == 'PT_LOAD' (1) and p_flags & 1 (Executable)
            if seg.header.p_type == 'PT_LOAD' and (seg.header.p_flags & 1):
                segments.append((seg.header.p_vaddr, seg.data()))
        return segments

    def extract_gadgets(self):
        """
         x86 
        """
        print(f"\n{Colors.CYAN}[*] Extracting ROP Gadgets (Max Bytes: {self.max_bytes})...{Colors.RESET}")
        
        exec_segments = self._get_executable_segments()
        if not exec_segments:
            print(f"{Colors.RED}[!] No executable segments found.{Colors.RESET}")
            return

        gadgets_found = set()

        for base_addr, data in exec_segments:
            ret_offsets = [i for i, b in enumerate(data) if b == 0xc3]
            
            for ret_idx in ret_offsets:
                for offset in range(1, self.max_bytes + 1):
                    start_idx = ret_idx - offset + 1
                    if start_idx < 0:
                        continue
                        
                    snippet = data[start_idx : ret_idx + 1]
                    snippet_addr = base_addr + start_idx
                    
                    insns = list(self.md.disasm(snippet, snippet_addr))
                    
                    if not insns:
                        continue
                    
                    if sum(i.size for i in insns) != len(snippet):
                        continue
                        
                    if insns[-1].mnemonic != 'ret':
                        continue
                        
                    if len(insns) > self.max_insn:
                        continue
                        
                    asm_text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                    gadgets_found.add((snippet_addr, asm_text))

        sorted_gadgets = sorted(list(gadgets_found), key=lambda x: x[0])
        print(f"{Colors.GREEN}[+] Found {len(sorted_gadgets)} valid gadgets.{Colors.RESET}\n")
        
        for addr, asm in sorted_gadgets:
            print(f"  {Colors.YELLOW}0x{addr:08x}{Colors.RESET} : {asm}")
        print()

def main():
    parser = argparse.ArgumentParser(description="ELF Analyzer & ROP Gadget Extractor")
    parser.add_argument("binary", help="Path to the target ELF binary")
    parser.add_argument("-b", "--bytes", type=int, default=16, help="Max bytes to search backward for gadgets (default: 16)")
    parser.add_argument("-i", "--insn", type=int, default=6, help="Max instructions per gadget (default: 6)")
    parser.add_argument("--no-gadget", action="store_true", help="Only check security mitigations, skip gadget extraction")
    
    args = parser.parse_args()

    analyzer = ELFAnalyzer(args.binary, max_gadget_bytes=args.bytes, max_insn=args.insn)
    
    analyzer.check_security_mitigations()
    
    if not args.no_gadget:
        analyzer.extract_gadgets()

if __name__ == "__main__":
    main()
