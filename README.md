# ppsspp-cwcheat-helpy

[![GitHub](https://img.shields.io/badge/GitHub-TAbdiukov/ppsspp--cwcheat--helpy-black?logo=github)](https://github.com/TAbdiukov/ppsspp-cwcheat-helpy)
[![PyPI Version](https://img.shields.io/pypi/v/ppsspp-cwcheat-helpy.svg)](https://pypi.org/project/ppsspp-cwcheat-helpy)
![License](https://img.shields.io/github/license/TAbdiukov/ppsspp-cwcheat-helpy)

[![buymeacoffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/tabdiukov)

**cwCheat address rewriter for PSP/PPSSPP memory patch lines.**

Helpy watches your clipboard for PSP virtual addresses such as `08801234`, converts them to cwCheat’s 28-bit offset, rewrites a cwCheat line template, prints the result, and copies it back to your clipboard.

## Table of contents

- [What this does](#what-this-does)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Templates and input formats](#templates-and-input-formats)
- [Address math & valid range](#address-math--valid-range)
- [Template detection](#template-detection)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

## What this does

Use this when you are finding addresses in PPSSPP or on hardware and want to keep reusing the same cwCheat template.

- Accepts a full cwCheat line or a single opcode nibble at startup.
- Watches for clipboard values like `08801234` or `0x08801234`.
- Rewrites only the detected 28-bit address field.
- Preserves the opcode nibble, the other word, and any `// comment`.
- Copies the rewritten `_L ...` line back to the clipboard.

## Installation

Install from PyPI:

```bash
pip install ppsspp-cwcheat-helpy
```

Helpy uses `pyperclip`, which is installed with the package. On Linux, you may also need a clipboard backend:

* Wayland: `wl-clipboard`
* X11: `xclip` or `xsel`

Windows and macOS usually need no extra clipboard utility.

## Quick start

```bash
ppsspp-cwcheat-helpy
```

Helpy prints the app version, accepted address range, active template, and a preview. With no argument, it uses a constant 32-bit write (`0x2`) with the address in the first word.

Copy `08801234`; Helpy prints and copies:

```text
_L 0x20001234 0x01234567 // helpy-automated: set address to 0x01234567
```

Stop with **Ctrl+C**.

## Templates and input formats

You may pass one template argument.

### Full cwCheat line

```text
_L 0x20000000 0x01234567 // set HP
20000000 01234567        // also OK
```

Rules:

- Two 32-bit hex words, with or without `0x`.
- Optional `_L` prefix.
- Optional `// comment`, preserved in output.

### Opcode nibble only

```text
2
E // skip if ==
0xD // single-line conditional
```

A single hex nibble chooses the code family. The second word starts as `0x01234567`; for `0xE`, the address goes in the second word, otherwise in the first.

If no argument is provided, or an unrecognised argument is provided, Helpy uses the default `0x2` template. A recognised line with no replaceable address field exits with an error.

## Address math & valid range

cwCheat uses a 28-bit address window into PSP user memory:

```text
offset = PSP - 0x08800000
valid PSP range = 0x08800000 .. 0x187FFFFF (inclusive)
```

Clipboard input must be 7-8 hex digits, optionally prefixed with `0x`. Invalid addresses are reported, and the watcher keeps running.

## Template detection

Helpy uses heuristics to decide where to place the 28-bit address field (`AAAAAAA`):

| Opcode top nibble | Meaning                     | Address goes to                   |
| ----------------- | --------------------------- | ---------------------------------- |
| `0x0`             | Constant write (8-bit)      | **w1**                             |
| `0x1`             | Constant write (16-bit)     | **w1**                             |
| `0x2`             | Constant write (32-bit)     | **w1**                             |
| `0x3`             | Increment/Decrement         | **w1**                             |
| `0x4`             | Multi-write (word)          | **w1**                             |
| `0x6`             | Pointer write               | **w1**                             |
| `0x7`             | Boolean op                  | **w1**                             |
| `0x8`             | Multi-write (byte/halfword) | **w1**                             |
| `0xD`             | Conditional (single-line)   | **w1**                             |
| `0xE`             | Conditional (multi-skip)    | **w2** (top nibble typically 0..3) |
| other             | Misc/other                  | best effort                        |

For full-line templates, Helpy preserves the opcode, parameters, values, and `// comment`, and replaces only the detected address field. For `0xD`, it rewrites the first-word address only.

## Examples

### Default template

```bash
ppsspp-cwcheat-helpy
```

Clipboard: `08801234`

```text
_L 0x20001234 0x01234567 // helpy-automated: set address to 0x01234567
```

### Full cwCheat line as template

```bash
ppsspp-cwcheat-helpy "_L 0x2003AD01 0x77777777 // speed hack 1"
```

Clipboard: `0x08804567`

```text
_L 0x20004567 0x77777777 // speed hack 1
```

### Opcode-only template for `0xE`

```bash
ppsspp-cwcheat-helpy "E // skip if =="
```

Clipboard: `08801234`

```text
_L 0xE0000000 0x00001234 // skip if ==
```

### Invalid address

Clipboard: `0x087FFFFF`

```text
*Invalid PSP address: 0x087FFFFF (PSP address below base)
```

## Troubleshooting

- **Nothing happens when I copy an address**: use `088xxxxx` ... `187xxxxx` or `0x...`, and copy it again if the clipboard did not change.
- **Linux clipboard errors**: install `wl-clipboard` for Wayland, or `xclip`/`xsel` for X11.
- **Clipboard content gets overwritten**: expected; Helpy copies the generated cheat line for quick pasting.

## Credits

- **Author**: Tim Abdiukov
- Thanks to the PPSSPP and cwCheat communities for documentation and examples.