#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
import random
import re

try:
    import pyperclip
except ModuleNotFoundError:
    print("Please install prerequisite,")
    print("```")
    print("pip install pyperclip")
    print("```")
    sys.exit(1)


class Helpy:
    """
    Helpy: cwCheat address rewriter.

    Behavior:
      - On startup, optionally parse a cwCheat line passed as arguments.
      - Detect which 32-bit word carries the 28-bit address field ("AAAAAAA").
      - Preserve command type, values, and comments; only swap the address.
      - Keep printing to stdout and copying to clipboard when the user copies
        a PSP address (e.g., 08801234) to the clipboard.
    """

    # PSP user-space base used by cwCheat address math (matches the original script)
    PSP_BASE = 0x08800000

    # Useful default for constant 32-bit write (type 0x2)
    OP_EDIT_4BYTES = 0x20000000

    # Regex to pull two hex words and an optional // comment from a cwCheat line
    CHEAT_LINE_RE = re.compile(
        r"""
        ^\s*(?:_L\b\s+)?                                  # optional '_L '
        (?P<w1>0x[0-9a-fA-F]{1,8}|[0-9a-fA-F]{1,8})\s+     # first 32-bit word
        (?P<w2>0x[0-9a-fA-F]{1,8}|[0-9a-fA-F]{1,8})        # second 32-bit word
        (?:\s*//\s*(?P<comment>.*))?                       # optional // comment
        \s*$""",
        re.VERBOSE,
    )

    def __init__(self):
        self.PROGRAM_NAME = "Helpy"
        # Runtime state
        self.template_w1 = None
        self.template_w2 = None
        self.comment = None
        self.addr_slot = None  # 'w1' or 'w2'
        self.initialized = False

    # ------------------------ low-level helpers ------------------------

    @staticmethod
    def _to_u32(val):
        return val & 0xFFFFFFFF

    @staticmethod
    def _hex32(val):
        return "0x{0:08X}".format(val & 0xFFFFFFFF)

    @staticmethod
    def _parse_hex_word(s):
        s = s.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        if not s or len(s) > 8 or not re.fullmatch(r"[0-9a-fA-F]{1,8}", s):
            return None
        return int(s, 16)

    @staticmethod
    def _clean_clip_text(s):
        return (s or "").strip()

    def _psp_to_cw_offset(self, psp_addr):
        """Convert PSP virtual address to cwCheat 28-bit offset; validate bounds."""
        if psp_addr is None:
            return None, "No address"
        if psp_addr < self.PSP_BASE:
            return None, "PSP address below base"
        offset = psp_addr - self.PSP_BASE
        if offset < 0 or offset > 0x0FFFFFFF:
            return None, "Address outside 28-bit cwCheat window"
        return offset, None

    # ------------------ cwCheat pattern understanding ------------------

    @staticmethod
    def _type_nibble(word):
        return (word >> 28) & 0xF

    def _detect_address_slot(self, w1, w2):
        """
        Decide where the 28-bit address lives, based on common cwCheat patterns.

        Heuristics:
          - Most code types store AAAAAAA in the low 28 bits of the FIRST word.
          - 0xE* (multi-skip conditionals): address is typically in SECOND word,
            whose top nibble is 0..3 (0=EQ, 1=NE, 2<, 3>).
          - 0xD* (single-step conditionals): FIRST word is 0xD AAAAAAA (address).
            Some comparison variants also put an address in the SECOND word with
            top nibble 4..7 (for compare-against-another-address). We only
            rewrite ONE address: prefer FIRST word.
        """
        t1 = self._type_nibble(w1)
        t2 = self._type_nibble(w2)

        # 0xE* -> second word carries 0/1/2/3 + AAAAAAA
        if t1 == 0xE and t2 in {0x0, 0x1, 0x2, 0x3}:
            return "w2"

        # 0xD* -> first word carries AAAAAAA; (we ignore potential second address)
        if t1 == 0xD:
            return "w1"

        # Common write / pointer / boolean / multi-write families use w1
        # (0x0,1,2 writes; 0x4/0x8 multi-write; 0x6 pointer; 0x7 boolean)
        if t1 in {0x0, 0x1, 0x2, 0x3, 0x4, 0x6, 0x7, 0x8}:
            return "w1"

        # Fallback: if first word isn't a likely address carrier but second looks like 0..3 + AAAAAAA
        if t2 in {0x0, 0x1, 0x2, 0x3}:
            return "w2"

        # No usable address field detected
        return None

    @staticmethod
    def _op_description(nib):
        return {
            0x0: "Constant write (8-bit)",
            0x1: "Constant write (16-bit)",
            0x2: "Constant write (32-bit)",
            0x3: "Increment/Decrement",
            0x4: "Multi-write (word)",
            0x6: "Pointer write",
            0x7: "Boolean op",
            0x8: "Multi-write (byte/halfword)",
            0xD: "Conditional (single-line)",
            0xE: "Conditional (multi-skip)",
        }.get(nib, "Unknown/other")

    # ------------------------ initialization ---------------------------

    def _init_from_argument(self, argline):
        """
        Initialize the rewrite template from a provided cwCheat line.
        Returns (ok: bool, message: str)
        """
        m = self.CHEAT_LINE_RE.match(argline or "")
        if not m:
            return False, "No/invalid cwCheat line; using default template."

        w1 = self._parse_hex_word(m.group("w1"))
        w2 = self._parse_hex_word(m.group("w2"))
        if w1 is None or w2 is None:
            return False, "Invalid hex words; using default template."

        addr_slot = self._detect_address_slot(w1, w2)
        if addr_slot is None:
            msg = "The provided instruction doesn't expose a replaceable address field."
            return False, msg

        self.template_w1 = self._to_u32(w1)
        self.template_w2 = self._to_u32(w2)
        self.comment = (m.group("comment") or "").strip()
        self.addr_slot = addr_slot
        self.initialized = True

        op_desc = self._op_description(self._type_nibble(self.template_w1))
        info = f"Detected cwCheat line (type 0x{self._type_nibble(self.template_w1):X}: {op_desc}). "
        if addr_slot == "w1":
            info += "Address field is in the FIRST 32-bit word."
        else:
            info += "Address field is in the SECOND 32-bit word."

        return True, info

    def _init_default_template(self):
        """Fallback when no/invalid argument is provided."""
        self.template_w1 = self.OP_EDIT_4BYTES  # 0x20000000 -> 0x2AAAAAAA when filled
        self.template_w2 = 0x01234567
        self.comment = "Helpy-automated: set address to 0x01234567"
        self.addr_slot = "w1"
        self.initialized = True
        return (
            True,
            "Using default template: constant 32-bit write; address lives in the FIRST word.",
        )

    # ---------------------- payload generation -------------------------

    def _render_line(self, w1, w2, comment):
        line = f"_L {self._hex32(w1)} {self._hex32(w2)}"
        if comment:
            line += f" // {comment}"
        return line

    def _with_address_offset(self, offset28):
        """
        Build a cwCheat line by inserting the 28-bit address offset into the
        appropriate 32-bit word, preserving the high command/type nibble.
        """
        if self.addr_slot == "w1":
            w1 = (self.template_w1 & 0xF0000000) | (offset28 & 0x0FFFFFFF)
            w2 = self.template_w2
        elif self.addr_slot == "w2":
            w1 = self.template_w1
            w2 = (self.template_w2 & 0xF0000000) | (offset28 & 0x0FFFFFFF)
        else:
            # Shouldn't happen if initialized correctly
            w1, w2 = self.template_w1, self.template_w2
        return self._render_line(w1, w2, self.comment)

    def _preview_random(self):
        """
        Produce a one-off preview using a random valid PSP address to show the mapping.
        """
        # Use a smallish offset so the example looks neat.
        offset = random.randint(0x00001000, 0x000FFFFF)
        psp_addr = self.PSP_BASE + offset
        preview = self._with_address_offset(offset)
        print("▒Preview with a random valid address:")
        print(preview)
        pyperclip.copy(preview)

    # --------------------------- main loop -----------------------------

    def _try_make_payload_from_clipboard(self, raw_text):
        s = self._clean_clip_text(raw_text)
        if not s:
            return False

        # Accept '08801234' or '0x08801234' (upper/lower ok)
        m = re.fullmatch(r"(?:0x)?([0-9a-fA-F]{7,8})", s)
        if not m:
            return False

        try:
            psp_val = int(m.group(1), 16)
        except ValueError:
            return False

        offset, err = self._psp_to_cw_offset(psp_val)
        if err:
            pay = f"*Invalid PSP address: {s} ({err})"
            print("▒Output:\n" + pay)
            pyperclip.copy(pay)
            return True

        payload = self._with_address_offset(offset)
        print("▒Output:\n" + payload)
        pyperclip.copy(payload)
        return True

    def run(self):
        print(self.PROGRAM_NAME + " greets you!")
        print("How to: Just copy a PSP address like 08801234 to the clipboard.")

        # Join all args beyond script name into one string to keep comments intact
        argline = " ".join(sys.argv[1:]).strip()

        ok, msg = self._init_from_argument(argline) if argline else (False, "")
        if not ok:
            if argline and "doesn't expose" in msg:
                # Valid parse but no address field -> inform and exit
                print(msg)
                sys.exit(2)
            # Fallback to default template
            ok, msg = self._init_default_template()

        print(msg)

        # If user provided a recognizable pattern, show what we caught
        if argline and self.initialized:
            print("Pattern recognized: I will preserve the opcode, parameters, values, and any comments.")
            self._preview_random()

        # Clipboard watcher
        try:
            last = None
            while True:
                cur = pyperclip.paste()
                if cur != last:
                    last = cur
                    made = self._try_make_payload_from_clipboard(cur)
                    # If the paste isn't a hex address, just ignore quietly
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nExiting...", end="")


if __name__ == "__main__":
    Helpy().run()
