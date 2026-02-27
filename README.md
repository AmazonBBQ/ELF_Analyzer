# ELF_Analyzer 🔍

> A lightweight, dependency-minimal ELF analysis and ROP gadget extraction tool built for CTF binary exploitation and security research.

## 🌟 Features

* **Security Mitigations Check (Checksec):** Instantly detects compiler-level protections including PIE, NX, Stack Canary, and RelRO.
* **Strict-Aligned ROP Gadget Extraction:** Employs a precise backward-byte-stepping algorithm to extract reliable ROP gadgets.
* **Zero Bloat:** Built purely on `pwntools` (for ELF parsing) and `capstone` (for disassembly) with a clean, colorized CLI interface.

## 🤔 Why write another Gadget Finder?

There are many great tools like `ROPgadget` and `Ropper`. However, this project was created as a deep-dive exercise into the Capstone Engine API and the structural complexities of **x86/x64 variable-length instruction decoding**. 

A common pitfall in naive, hand-rolled gadget finders is slicing a fixed number of bytes backward from a `ret` instruction. In x86, doing this often lands the disassembler in the middle of a multi-byte instruction, leading to **Instruction Misalignment** and producing garbage (fake) instructions. 

**The Solution:** VulnLens implements a strict dynamic-offset backtracking algorithm. It steps backward byte-by-byte from the `ret` opcode (`0xc3`), disassembles the snippet, and rigorously verifies that the total length of the decoded instruction stream perfectly matches the byte slice length. This guarantees 100% instruction alignment.

## 🛠️ Installation

Ensure you have Python 3 installed. Clone the repository and install the minimal dependencies:

```bash
git clone [https://github.com/yourusername/VulnLens.git](https://github.com/yourusername/VulnLens.git)
cd VulnLens
pip install pwntools capstone
🚀 Usage
Bash
usage: elf_analyzer.py [-h] [-b BYTES] [-i INSN] [--no-gadget] binary

positional arguments:
  binary                Path to the target ELF binary

options:
  -h, --help            show this help message and exit
  -b BYTES, --bytes BYTES
                        Max bytes to search backward for gadgets (default: 16)
  -i INSN, --insn INSN  Max instructions per gadget (default: 6)
  --no-gadget           Only check security mitigations, skip gadget extraction
🎯 Example & Workflow
1. Basic Scanning
Run the analyzer against your target binary to map out the security landscape and harvest gadgets.

Bash
$ python3 elf_analyzer.py ./vuln_test

[*] Security Mitigations for ./vuln_test:
  [-] PIE       : Disabled
  [+] NX        : Enabled
  [+] Canary    : Enabled
  [-] RelRO     : Disabled

[*] Extracting ROP Gadgets (Max Bytes: 16)...
[+] Found 114 valid gadgets.

  0x00401016 : ret
  ...
  0x0040117d : pop rdi ; ret
  0x00401194 : leave ; ret
2. Tactical Approach (Handling PIE & Canary)
When dealing with modern binaries, VulnLens acts as your reconnaissance radar:

If Canary is Enabled: The tool warns you that a direct stack smash will trigger __stack_chk_fail. You must first find an Info Leak (e.g., Format String) to bypass the cookie before executing your ROP chain.

If PIE is Enabled: The addresses outputted by VulnLens serve as relative offsets. You will need to leak the runtime Base Address and dynamically calculate the real payload addresses (Runtime_Base + Gadget_Offset).
