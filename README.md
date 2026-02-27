# ELF_Analyzer 🔍 (VulnLens)

A lightweight, dependency-minimal ELF analysis and ROP gadget extraction tool built for CTF binary exploitation and security research.

---

## Features

- **Security Mitigations Check (Checksec):** Detects PIE, NX, Stack Canary, and RelRO.
- **Strict-Aligned ROP Gadget Extraction:** Uses a backward byte-stepping algorithm to extract *reliable* gadgets.
- **Zero Bloat:** Minimal stack — `pwntools` (ELF parsing) + `capstone` (disassembly) with a clean, colorized CLI.

---

## Why write another Gadget Finder?

There are many great tools like `ROPgadget` and `Ropper`. This project exists as a deep-dive into the Capstone Engine API and the structural complexity of **x86/x64 variable-length instruction decoding**.

A common pitfall in naive gadget finders is slicing a fixed number of bytes backward from a `ret` instruction. On x86/x64, this often lands the disassembler in the middle of a multi-byte instruction, causing **instruction misalignment** and producing garbage (fake) instructions.

### The Solution: strict alignment verification

VulnLens steps backward byte-by-byte from the `ret` opcode (`0xC3`), disassembles candidate slices, and **only accepts** a gadget when the decoded instruction stream length matches the slice length exactly. This guarantees correct alignment.

---

## Installation

Requirements:

- Python 3.8+ (recommended)
- `pwntools`, `capstone`

```bash
git clone https://github.com/yourusername/VulnLens.git
cd VulnLens
pip install pwntools capstone
```

> Tip: If you use a virtual environment:
>
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -U pip
> pip install pwntools capstone
> ```

---

## Usage

```text
usage: elf_analyzer.py [-h] [-b BYTES] [-i INSN] [--no-gadget] binary

positional arguments:
  binary                Path to the target ELF binary

options:
  -h, --help            show this help message and exit
  -b BYTES, --bytes BYTES
                        Max bytes to search backward for gadgets (default: 16)
  -i INSN, --insn INSN  Max instructions per gadget (default: 6)
  --no-gadget           Only check security mitigations, skip gadget extraction
```

---

## Example Workflow

### 1) Basic scanning

Run the analyzer against your target binary to map out mitigations and harvest gadgets.

```bash
python3 elf_analyzer.py ./vuln_test
```

Example output:

```text
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
```

### 2) Tactical interpretation (PIE & Canary)

Use the results as a quick recon radar:

- **If Canary is enabled:** A direct stack smash likely triggers `__stack_chk_fail`. You typically need an **info leak** (e.g., format string, OOB read) to recover the canary before building a working ROP chain.
- **If PIE is enabled:** Gadget addresses should be treated as **offsets**. Leak the runtime base address first, then compute:
  - `runtime_addr = base + gadget_offset`

---

## Notes

- Gadget quality depends on correct decode boundaries. The alignment validation step is the core of this tool’s reliability.
- If you want to extend it, good next steps are:
  - multi-`ret` patterns (e.g., `retf`, `sysret` handling),
  - filtering by register effects (e.g., “clean `pop rdi ; ret` only”),
  - exporting results as JSON for exploit scripts.
