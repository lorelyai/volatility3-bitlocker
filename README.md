# volatility3-bitlocker

Volatility 3 plugin for extracting BitLocker Full Volume Encryption Keys (FVEK).

## What it does

* Scans Windows kernel pools (Tags: `FVEc`, `Cngb`, `None`, `dFVE`, or custom)
* Validates AES key schedules (176/240 bytes) to recover FVEK and (when present) the XTS tweak
* Optionally writes a Dislocker-ready `.fvek` file

## Tested on

* **Volatility 3 Framework**: 2.26.0
* **Target**: Intel x64, Windows 10+
* **Note**: The key-schedule search should work on any Windows system. The Dislocker works properly only on the Win10+ x64 layout.

## Installation

Place the plugin file in your Volatility 3 plugins path (e.g., `volatility3/plugins/windows/bitlocker.py`).

## Usage

### Scan memory and emit Dislocker files

```bash
vol -f memdump.mem -vvv windows.bitlocker.BitlockerFVEKScan \
  --tags FVEc Cngb None --dislocker
```

**Options**

* `--tags`   : pool tags to scan (space separated)
* `--dump`   : write raw key bytes per hit (FVEK||tweak)
* `--dislocker` : write a Dislocker-ready `*.fvek` per hit

The TreeGrid output lists: PoolOffset, PoolTag, Cipher, FVEK, Tweak, PoolSize.
When `--dislocker` is set, you'll also get files like `0x*-Dislocker.fvek`.

## Mounting the encrypted disk

You have two paths:

### 1) Using **Dislocker** (with generated `.fvek`)

```bash
sudo mkdir /mnt/dislocker /mnt/decrypted
sudo dislocker -v -k 0x8087865bead0-Dislocker.fvek \
  -V bitlocker-2.dd /mnt/dislocker
sudo mount -t ntfs-3g /mnt/dislocker/dislocker-file /mnt/decrypted
```

### 2) Using **libbde/bdemount** (with raw keys)

Use `bdemount` when you have the **raw FVEK and TWEAK** (XTS) as hex:

```bash
sudo bdemount -o 0 -k <FVEK_HEX>:<TWEAK_HEX> bitlocker-2.dd /mnt/decrypted
```

## Contributing / Issues

If you have memory images to analyze or found bugs, please open an issue.
PRs improving tag coverage, heuristics, or fast-path robustness are welcome.

Thanks :)

---
