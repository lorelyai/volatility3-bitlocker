# Volatility 3 BitLocker plugin
#
# Plugin: windows.bitlocker_fvek_scan
# Purpose: Heuristically scan Windows kernel pools for BitLocker Full Volume Encryption Keys (FVEK)
#          using AES key schedule validation, adapted from older Volatility 2 approach.
#
# How it works (high level):
#   * Uses PoolScanner to iterate pool allocations with tags commonly used by BitLocker modules
#     across Windows versions ('FVEc', 'Cngb', 'None', 'dFVE' or custom 4 symbols).
#   * For each candidate pool block, reads the entire allocation and searches byte-by-byte for
#     data that validates as an AES-128/256 expanded key schedule (176/240 bytes respectively).
#   * Collects up to two keys per pool block (primary FVEK + optional tweak/secondary), exposes
#     them in the TreeGrid, and optionally emits a file containing the raw key bytes.
#
# Volatility 2 original plugin:   Marcin Ulikowski, https://github.com/elceef/bitlocker
# Volatility 3 plugin:            lorelyai, https://github.com/lorelyai/volatility3-bitlocker
# license:                        GNU General Public License v2.0 --> v3.0
# 

from __future__ import annotations

import logging
from typing import Generator, Iterable, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Avoid import-time circular dependencies by only type-check importing
    from volatility3.framework.plugins.windows import poolscanner as _ps

class BitlockerFVEKScan(interfaces.plugins.PluginInterface):
    """Scan kernel pools for BitLocker FVEK candidates using AES key schedule validation.

    This is a Volatility 3 rewrite of the classic Volatility 2 BitLocker pool scanner
    that detected AES keys by checking for valid expanded key schedules. It
    avoids version-specific offsets by validating schedules generically and theoretically
    should be sound across Windows releases.
    """
    
    _version = (1, 0, 0) 
    _required_framework_version = (2, 0, 0)

    # AES S-box and Rcon tables (from FIPS-197)
    _SBOX: Sequence[int] = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    _RCON: Sequence[int] = (
        0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
        0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72,
        0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66,
        0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB,
    )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel"
            ),
            requirements.ListRequirement(
                name="tags",
                description="Pool tags to scan (e.g., FVEc, Cngb, None, dFVE)",
                element_type=str,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Emit a file per hit containing raw key bytes",
                default=False,
                optional=True,
            ),
            
            requirements.BooleanRequirement(
                name="dislocker",
                description="Emit a Dislocker-ready 66-byte FVEK file per hit",
                default=False,
                optional=True,
            ),
        ]

    # === AES helpers ===
    @staticmethod
    def _rot_word(word: List[int]) -> List[int]:
        return word[1:] + word[:1]

    def _core(self, word: List[int], iteration: int) -> List[int]:
        word = self._rot_word(word)
        for i in range(4):
            word[i] = self._SBOX[word[i]]
        word[0] ^= self._RCON[iteration]
        return word

    def _valid_schedule(self, schedule: bytes, key_size: int, expanded_len: int) -> bool:
        """Validate that *schedule* is a correct AES expanded key for a key of *key_size* bytes.
        """
        if len(schedule) != expanded_len:
            return False
        key = list(schedule[:key_size])
        expanded = [0] * expanded_len
        # Copy original key
        for j in range(key_size):
            expanded[j] = key[j]
        current_size = key_size
        rcon_iter = 1
        # Expand
        while current_size < expanded_len:
            t = expanded[current_size - 4 : current_size].copy()
            if current_size % key_size == 0:
                t = self._core(t, rcon_iter)
                rcon_iter += 1
            # Additional sbox step for 256-bit keys
            if key_size == 32 and (current_size % key_size) == 16:
                for i in range(4):
                    t[i] = self._SBOX[t[i]]
            for m in range(4):
                expanded[current_size] = expanded[current_size - key_size] ^ t[m]
                # Early exit on mismatch vs provided schedule
                if expanded[current_size] != schedule[current_size]:
                    return False
                current_size += 1
        return True
        
    # === Dislocker helpers ===
    @staticmethod
    def _dislocker_header_xts(key_bits: int) -> bytes:
        # Win10+ XTS ids match V2: 0x8004 (128), 0x8005 (256)
        low = 0x04 if key_bits == 128 else 0x05
        return bytes([low, 0x80])

    @staticmethod
    def _dislocker_header_cbc(key_bits: int, diffuser: bool = False) -> bytes:
        if diffuser:
            low = 0x01 if key_bits == 256 else 0x00
        else:
            low = 0x03 if key_bits == 256 else 0x02
        return bytes([low, 0x80])

    def _write_dislocker_file(self, pool_offset: int, header: bytes, body64: bytes) -> str:
        data = header + body64
        path = f"{pool_offset:#x}-Dislocker.fvek"
        with self.open(path) as fh:
            fh.write(data)
        return path

    # === Scan/generate ===
    def _get_poolscanner(self):
        # Lazy import to avoid circular import during plugin discovery
        from volatility3.plugins.windows import poolscanner as ps
        return ps

    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]

        # Determine alignment based on pointer width (8 bytes for 32-bit pools, 16 for 64-bit)
        bits = getattr(layer, "bits_per_register", 64)
        pool_alignment = 16 if bits == 64 else 8

        tags = self.config.get("tags", None)
        if tags:
            tag_bytes = [t.encode("ascii", "ignore")[:4] for t in tags]
        else:
            tag_bytes = [b"FVEc", b"Cngb", b"None", b"dFVE"]

        ps = self._get_poolscanner()
        try:
            constraints = ps.PoolScanner.builtin_constraints(kernel.symbol_table_name, tags=tag_bytes)
        except TypeError:
            constraints = None
        if not constraints:
            try:
                constraints = ps.PoolScanner.builtin_constraints(kernel.symbol_table_name, tags_filter=tag_bytes)
            except TypeError:
                constraints = []
        if not constraints:
            type_name = kernel.symbol_table_name + "!_POOL_HEADER"
            constraints = [ps.PoolConstraint(type_name=type_name, tag=t) for t in tag_bytes]
    
        # Iterate pool headers that match our tags
        for constraint, pool in ps.PoolScanner.pool_scan(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            pool_constraints=constraints,
            alignment=pool_alignment,
        ):
            try:
                pool_offset = int(pool.vol.offset)
                block_size_units = int(pool.BlockSize)
                pool_size = block_size_units * pool_alignment
                if pool_size <= 0 or pool_size > 1024 * 1024:
                    continue
                buf = layer.read(pool_offset, pool_size, pad=True)
            except exceptions.InvalidAddressException:
                continue
            except Exception as e:
                vollog.debug(f"Failed reading pool @ {pool_offset:#x}: {e}")
                continue

            # ---- Dislocker fast-path ----
            disl_path = ""
            want_disl = bool(self.config.get("dislocker", False))
            is_x64 = (pool_alignment == 16)
            tag_bytes_this = getattr(constraint, "tag", b"") if hasattr(constraint, "tag") else b""
            if want_disl and tag_bytes_this in ([b"None", b"dFVE"]) and is_x64 and 1230 <= pool_size <= 1450:

                if len(buf) >= 0xE0 + 64:
                    f1 = buf[0x9C:0x9C + 64]
                    f2 = buf[0xE0:0xE0 + 64]
                    f3 = buf[0xC0:0xC0 + 64] if len(buf) >= 0xC0 + 64 else b""
    
                    def _write_disl(header: bytes, body: bytes) -> str:
                        path = f"{pool_offset:#x}-Dislocker.fvek"
                        with self.open(path) as fh:
                            fh.write(header + body)
                        return path

                    if f1 and f2 and f1[:16] == f2[:16]:
                        if f1[16:32] == f2[16:32]:
                            hdr = b"\x04\x80"  # XTS-128
                        else:
                            hdr = b"\x05\x80"  # XTS-256
                        try:
                            disl_path = _write_disl(hdr, f1)
                            vollog.info(f"[DISL] FVEK for Dislocker dumped to file: ./{disl_path}")
                        except Exception as e:
                            vollog.debug(f"Failed to write Dislocker FVEK (Win10 fast-path) for {pool_offset:#x}: {e}")
                    elif f1 and f3 and f1[:16] == f3[:16]:
                        if f1[16:32] == f3[16:32]:
                            hdr = b"\x03\x80"  # CBC-256
                        else:
                            hdr = b"\x02\x80"  # CBC-128
                        try:
                            disl_path = _write_disl(hdr, f1)
                            vollog.info(f"[DISL] FVEK for Dislocker dumped to file: ./{disl_path}")
                        except Exception as e:
                            vollog.debug(f"Failed to write Dislocker FVEK (CBC path) for {pool_offset:#x}: {e}")

            # ---- Heuristic AES schedule search ----
            hits: List[bytes] = []
            # AES-128 expanded schedule is 176 bytes
            for i in range(8, max(8, pool_size - 176)):
                chunk = buf[i : i + 176]
                if len(chunk) < 176:
                    break
                if self._valid_schedule(chunk, 16, 176):
                    hits.append(chunk[:16])
                    if len(hits) == 2:
                        break
            # AES-256 expanded schedule is 240 bytes
            if len(hits) < 2:
                for i in range(8, max(8, pool_size - 240)):
                    chunk = buf[i : i + 240]
                    if len(chunk) < 240:
                        break
                    if self._valid_schedule(chunk, 32, 240):
                        hits.append(chunk[:32])
                        if len(hits) == 2:
                            break

            if not hits:
                continue

            fvek = hits[0]
            tweak = hits[1] if len(hits) > 1 else b""
            cipher = f"AES-{len(fvek) * 8}"

            # If no fast-path, fallback (NOT TESTED PROPERLY)
            if want_disl and not disl_path:
                try:
                    # Default to XTS mapping for modern images: 0x8004 (128) / 0x8005 (256)
                    header = b"\x05\x80" if len(fvek) == 32 else b"\x04\x80"
                    body = (fvek + (tweak or b"")).ljust(64, b"\x00")
                    path = f"{pool_offset:#x}-Dislocker.fvek"
                    with self.open(path) as fh:
                        fh.write(header + body)
                    disl_path = path
                    vollog.info(f"[DISL] FVEK for Dislocker dumped to file: ./{disl_path}")
                except Exception as e:
                    vollog.debug(f"Failed to write Dislocker FVEK (fallback) for {pool_offset:#x}: {e}")

            # Print friendly info logs
            vollog.info(f"[FVEK] Address : {pool_offset:#x}")
            vollog.info(f"[FVEK] Cipher: AES-XTS {len(fvek) * 8} bit (Win 10+)")
            vollog.info(f"[FVEK] FVEK: {fvek.hex()}")

            # Optionally write a file per hit using the UI file handler
            if self.config.get("dump", False):
                try:
                    preferred = f"{pool_offset:#x}.fvek"
                    with self.open(preferred) as fh:
                        fh.write(fvek + tweak)
                except Exception as e:
                    vollog.debug(f"Failed to dump FVEK for {pool_offset:#x}: {e}")

            yield (
                0,
                (
                    format_hints.Hex(pool_offset),
                    tag_bytes_this.decode(errors="ignore") if tag_bytes_this else "?",
                    cipher,
                    fvek.hex(),
                    tweak.hex() if tweak else "",
                    pool_size,
                ),
            )


    # === Plugin entrypoint ===
    def run(self) -> interfaces.renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PoolOffset", format_hints.Hex),
                ("PoolTag", str),
                ("Cipher", str),
                ("FVEK", str),
                ("Tweak", str),
                ("PoolSize", int),
            ],
            self._generator(),
        )
