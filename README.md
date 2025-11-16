# ppsspp-cwcheat-helpy

**cwCheat address rewriter for PSP/PPSSPP memory patch lines.**  
Copies a PSP virtual address from your clipboard, converts it to the cwCheat 28-bit offset, and rewrites a cwCheat line while preserving opcode, values, and comments. It continuously watches your clipboard, prints the new line, and also copies it back to the clipboard.

---

## Table of contents

- [What this does](#what-this-does)
- [How it works (in short)](#how-it-works-in-short)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Input formats](#input-formats)
- [Address math & valid range](#address-math--valid-range)
- [Template detection (which word holds the address?)](#template-detection-which-word-holds-the-address)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

---

## What this does

Most cwCheat commands encode a **28-bit address field** ('AAAAAAA') inside one of the two 32-bit words of a cheat line. When you’re hunting values in PPSSPP or on hardware, you often need to keep swapping different PSP addresses into the **same** cheat template. Doing this by hand is tedious and error-prone.

This tool lets you:

- Start with a **template** (a full cwCheat line or just an opcode nibble).
- Keep copying PSP addresses like `08801234` from whatever tool you use.
- Get a correctly rewritten cwCheat line instantly (printed **and** copied to clipboard).

---

## How it works (in short)

- On startup, Helpy:
  - Prints a how-to banner and the acceptable address range.
  - Optionally parses **one** argument:
    - a full cwCheat line (`_L 0x20000000 0x01234567 // comment`), or
    - a **single opcode nibble** (e.g., `2`, `E`, or `0xD`) with optional `// comment`.
  - Figures out **which 32-bit word (w1 or w2)** contains the 28-bit address.
  - Shows a preview line using a random valid address.

- Then it **watches the clipboard**. When it sees a PSP address (`08801234` or `0x08801234`), it:
  - Validates that it's within the cwCheat addressable window.
  - Converts PSP ? cwCheat offset: `offset = PSP - 0x08800000`.
  - Rewrites the template, preserving the opcode nibble, values, and any `// comment`.
  - Prints the new line and copies it back to the clipboard.

---

## Installation

### From PyPi

```bash
pip install ppsspp-cwcheat-helpy
````


If you prefer isolated CLI installs, consider [`pipx`](https://pypa.github.io/pipx/):

```bash
pipx install "git+https://github.com/TAbdiukov/ppsspp-cwcheat-helpy@main"
```

### Runtime requirement: clipboard support

`pyperclip` needs a system clipboard utility on Linux/\*BSD:

* Wayland: `wl-clipboard` (package `wl-clipboard`)
* X11: `xclip` or `xsel`

On Windows and macOS, no extra packages are required.

---

## Quick start

Run:

```bash
ppsspp-cwcheat-helpy
```

You'll see:

```
ppsspp-cwcheat-helpy 0.2.0
How to: Just copy a PSP address like 08801234 to the clipboard.
Acceptable cwCheat address range: 0x08800000 - 0x187FFFFF (inclusive)
Accepted input formats: 08801234 or 0x08801234
Using default template: constant 32-bit write; address lives in the FIRST word.
...
```

Now copy any valid PSP address (e.g., `08801234`). The tool prints a new cwCheat line and places it on your clipboard.

Stop with **Ctrl+C**.

---

## Input formats

You can provide **one** argument at startup to set the template:

1. **Full cwCheat line** (with optional `_L` and `// comment`):

   ```
   _L 0x20000000 0x01234567 // set HP
   20000000 01234567        // also OK (no 0x, no _L, no comment)
   ```

   * Two 32-bit hex words (with or without `0x`).
   * Optional `_L` prefix (ignored).
   * Optional `// ...` comment (preserved).

2. **Opcode nibble only** (with optional `// comment`):

   ```
   2            // constant 32-bit write
   E // multi-skip conditional
   0xD // single-line conditional
   ```

   * A single hex nibble chooses the code **family** and sets a sensible default for which word holds the address.
   * The second word is seeded with `0x01234567` as a visible placeholder.

If no argument is provided, Helpy uses the **default template**:

```
type 0x2 (constant 32-bit write), address in the FIRST word;
second word = 0x01234567;
comment = "helpy-automated: set address to 0x01234567"
```

---

## Address math & valid range

* cwCheat uses a **28-bit window** into PSP user memory.
* **Base**: `0x08800000`
  **Offset**: `offset = PSP - 0x08800000` (must fit in 28 bits).
* **Valid PSP range accepted by the tool**:

  ```
  0x08800000 .. 0x187FFFFF   (inclusive)
  ```
* Accepted clipboard formats: `08801234` or `0x08801234` (7-8 hex digits).

If the address is invalid, Helpy prints an informative error and continues watching the clipboard.

---

## Template detection (which word holds the address?)

Heuristics used to decide where to place the 28-bit address (AAAAAAA):

| Opcode top nibble | Meaning (short)             | Address goes to                   |
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

When you pass a **full line**, Helpy preserves the opcode, parameters, values, and `// comment`, and only replaces the address field in the detected word.

---

## Examples

### 1) No argument (default template)

Start:

```bash
python -m ppsspp_cwcheat_helpy.helpy
```

Copy `08801234` to your clipboard. Output:

```
_L 0x20001234 0x01234567 // helpy-automated: set address to 0x01234567
```

(Offset `0x00001234` is inserted into the **first** word, preserving the `0x2` type nibble.)

---

### 2) Full cwCheat line as a template

Start with a line you want to keep (including comment):

```bash
python -m ppsspp_cwcheat_helpy.helpy "_L 0x2003AD01 0x77777777 // speed hack 1"
```

Copy `0x08804567`. Output:

```
_L 0x20004567 0x77777777 // speed hack 1
```

Only the address field changed.

---

### 3) Opcode-only template (multi-skip conditional, `0xE`)

```bash
python -m ppsspp_cwcheat_helpy.helpy "E // skip if =="
```

Copy `08801234`. Output:

```
_L 0xE0000000 0x00001234 // skip if ==
```

Here, `0xE` places the address in the **second** word, whose top nibble is typically `0..3` depending on comparison mode. Helpy preserves the top nibble of your placeholder second word.

---

### 4) Invalid address example

Copy `0x087FFFFF` (below base). Output:

```
*Invalid PSP address: 0x087FFFFF (PSP address below base)
```

Helpy keeps watching for the next clipboard change.

---

## Troubleshooting

* **Nothing happens when I copy an address**

  * Make sure the address is `088xxxxx` ... `187xxxxx` and is 7-8 hex digits.
  * The tool only reacts when the clipboard **changes**. Try copying again.
  * On Linux, ensure `wl-copy/wl-paste` (Wayland) or `xclip`/`xsel` (X11) is installed.

* **Clipboard content gets overwritten**

  * That's intended: when Helpy recognizes a PSP address, it copies the new cwCheat line to your clipboard for quick paste back into your cheat file.

---

## Credits

* **Author**: Tim Abdiukov
* Thanks to the PPSSPP and cwCheat communities for documentation and examples.

---
