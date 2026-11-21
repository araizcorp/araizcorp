# File Signatures & Magic Bytes Cheat Sheet

A practical quick reference for identifying files by their binary header instead of trusting the extension.

**Español:** referencia rápida para identificar archivos mediante su cabecera binaria.  
**Deutsch:** Kurzreferenz zur Dateierkennung anhand binärer Header.

> Part of the [AraizCorp](https://araizcorp.tech) open technical resource collection. Explore more material at [AraizCorp Academy](https://academy.araizcorp.tech).

## Quick triage

```bash
file suspicious.bin
xxd -l 64 suspicious.bin
hexdump -C -n 64 suspicious.bin
strings -a -n 6 suspicious.bin | head
binwalk suspicious.bin
exiftool suspicious.bin
```

## Common signatures

| Format | Hex signature | ASCII | Typical extension |
|---|---|---|---|
| PDF | `25 50 44 46 2D` | `%PDF-` | `.pdf` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` | `.png` |
| JPEG | `FF D8 FF` | — | `.jpg`, `.jpeg` |
| GIF87a | `47 49 46 38 37 61` | `GIF87a` | `.gif` |
| GIF89a | `47 49 46 38 39 61` | `GIF89a` | `.gif` |
| WebP | `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | `RIFF....WEBP` | `.webp` |
| BMP | `42 4D` | `BM` | `.bmp` |
| TIFF little endian | `49 49 2A 00` | `II*.` | `.tif`, `.tiff` |
| TIFF big endian | `4D 4D 00 2A` | `MM.*` | `.tif`, `.tiff` |
| ZIP / Office Open XML / JAR | `50 4B 03 04` | `PK..` | `.zip`, `.docx`, `.xlsx`, `.jar` |
| Empty ZIP | `50 4B 05 06` | `PK..` | `.zip` |
| RAR v4 | `52 61 72 21 1A 07 00` | `Rar!...` | `.rar` |
| RAR v5 | `52 61 72 21 1A 07 01 00` | `Rar!....` | `.rar` |
| 7-Zip | `37 7A BC AF 27 1C` | `7z..'.` | `.7z` |
| GZIP | `1F 8B` | — | `.gz` |
| BZIP2 | `42 5A 68` | `BZh` | `.bz2` |
| XZ | `FD 37 7A 58 5A 00` | `.7zXZ.` | `.xz` |
| ELF | `7F 45 4C 46` | `.ELF` | Linux binaries |
| PE / DOS executable | `4D 5A` | `MZ` | `.exe`, `.dll`, `.sys` |
| Mach-O 32-bit | `FE ED FA CE` | — | macOS binary |
| Mach-O 64-bit | `FE ED FA CF` | — | macOS binary |
| Java class | `CA FE BA BE` | — | `.class` |
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `SQLite format 3.` | `.sqlite`, `.db` |
| Windows Registry hive | `72 65 67 66` | `regf` | Registry hive |
| PCAP | `D4 C3 B2 A1` | — | `.pcap` |
| PCAPNG | `0A 0D 0D 0A` | — | `.pcapng` |
| OLE Compound File | `D0 CF 11 E0 A1 B1 1A E1` | — | legacy Office, MSI |
| RTF | `7B 5C 72 74 66 31` | `{\\rtf1` | `.rtf` |
| XML / SVG | `3C 3F 78 6D 6C` | `<?xml` | `.xml`, `.svg` |
| UTF-8 BOM | `EF BB BF` | — | text |
| UTF-16 LE BOM | `FF FE` | — | text |
| UTF-16 BE BOM | `FE FF` | — | text |

## Container formats need a second check

Several formats share ZIP or RIFF signatures. Inspect internal names before deciding the real type.

```bash
unzip -l sample.bin | head -50
7z l sample.bin
zipinfo sample.bin
strings -a sample.bin | grep -E 'word/|xl/|ppt/|META-INF/'
```

Common ZIP based indicators:

| Internal path | Likely format |
|---|---|
| `word/document.xml` | DOCX |
| `xl/workbook.xml` | XLSX |
| `ppt/presentation.xml` | PPTX |
| `META-INF/MANIFEST.MF` | JAR |
| `AndroidManifest.xml` | APK |
| `mimetype` containing `epub+zip` | EPUB |

## Search for embedded files

```bash
binwalk target.bin
binwalk -e target.bin
foremost -i target.bin -o carved
bulk_extractor -o bulk-output target.bin
grep -aob $'\x25\x50\x44\x46' target.bin
grep -aob $'\x50\x4b\x03\x04' target.bin
```

## Validate MIME detection

```bash
file --mime-type target.bin
xdg-mime query filetype target.bin
python3 - <<'PY'
import mimetypes
print(mimetypes.guess_type("target.bin"))
PY
```

Extension based MIME detection is only a hint. Confirm the header and, for containers, inspect their internal structure.

## Python header inspection

```python
from pathlib import Path

path = Path("sample.bin")
header = path.read_bytes()[:32]
print(header.hex(" "))
print(repr(header))
```

## Defensive workflow

1. Preserve the original file and calculate hashes.
2. Identify the header without opening the file in its native application.
3. Compare extension, MIME type and magic bytes.
4. Inspect container contents safely.
5. Look for appended or embedded data.
6. Record offsets and extraction commands.
7. Analyze active content in an isolated laboratory.

```bash
sha256sum suspicious.bin
stat suspicious.bin
file suspicious.bin
xxd -l 64 suspicious.bin
binwalk suspicious.bin
exiftool suspicious.bin
```

## Responsible use

Use this material only for files and systems you are authorized to examine. The commands are intended for incident response, forensic triage, CTF laboratories and defensive security research.

---

[AraizCorp](https://araizcorp.tech) · [Academy](https://academy.araizcorp.tech) · [Writeups](https://academy.araizcorp.tech/writeups/)
