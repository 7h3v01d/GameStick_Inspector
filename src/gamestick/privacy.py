from __future__ import annotations

import re
from typing import Optional

# Library roots whose immediate child names commonly contain catalogue/user data.
# Default evidence therefore exports counts and recognized platform semantics, not
# arbitrary filenames or directory names from these roots.
ROM_LIBRARY_ROOT_NAMES = frozenset({"rom", "roms", "games"})
ARTWORK_LIBRARY_ROOT_NAMES = frozenset({
    "image", "images", "artwork", "boxart", "boxarts", "cover", "covers",
    "snap", "snaps", "preview", "previews", "screenshot", "screenshots",
    "thumbnail", "thumbnails",
})
PRIVACY_LIBRARY_ROOT_NAMES = ROM_LIBRARY_ROOT_NAMES | ARTWORK_LIBRARY_ROOT_NAMES

# Exact, conservative aliases only. These are structural platform identifiers,
# not fuzzy guesses. Unknown child directory names remain private and contribute
# counts only.
_PLATFORM_ALIASES = {
    "fc": "FC",
    "famicom": "FC",
    "nes": "NES",
    "sfc": "SFC",
    "superfamicom": "SFC",
    "snes": "SNES",
    "gb": "GB",
    "gameboy": "GB",
    "gbc": "GBC",
    "gameboycolor": "GBC",
    "gba": "GBA",
    "gameboyadvance": "GBA",
    "n64": "N64",
    "nds": "NDS",
    "ds": "NDS",
    "3ds": "3DS",
    "ps": "PS1",
    "ps1": "PS1",
    "psx": "PS1",
    "psp": "PSP",
    "md": "MD",
    "megadrive": "MD",
    "genesis": "GENESIS",
    "sms": "SMS",
    "mastersystem": "SMS",
    "gg": "GG",
    "gamegear": "GG",
    "pce": "PCE",
    "pcengine": "PCE",
    "tg16": "TG16",
    "turbografx16": "TG16",
    "mame": "MAME",
    "arcade": "ARCADE",
    "fba": "FBA",
    "fbneo": "FBNEO",
    "neogeo": "NEOGEO",
    "cps1": "CPS1",
    "cps2": "CPS2",
    "cps3": "CPS3",
    "atari2600": "ATARI2600",
    "a2600": "ATARI2600",
    "atari5200": "ATARI5200",
    "a5200": "ATARI5200",
    "atari7800": "ATARI7800",
    "a7800": "ATARI7800",
    "lynx": "LYNX",
    "ws": "WS",
    "wonderswan": "WS",
    "wsc": "WSC",
    "wonderswancolor": "WSC",
    "msx": "MSX",
    "msx2": "MSX2",
    "dos": "DOS",
    "scummvm": "SCUMMVM",
    "amiga": "AMIGA",
    "c64": "C64",
    "commodore64": "C64",
    "dc": "DC",
    "dreamcast": "DC",
    "saturn": "SATURN",
    "pcfx": "PCFX",
    "ngp": "NGP",
    "ngpc": "NGPC",
    "vectrex": "VECTREX",
    "coleco": "COLECO",
    "colecovision": "COLECO",
    "intellivision": "INTELLIVISION",
}


def canonical_platform_name(value: object) -> Optional[str]:
    """Return a known canonical platform token, or ``None`` for arbitrary data."""
    text = str(value).strip().casefold()
    normalized = re.sub(r"[^a-z0-9]+", "", text)
    if not normalized:
        return None
    return _PLATFORM_ALIASES.get(normalized)


def is_privacy_library_root(name: object) -> bool:
    return str(name).strip().casefold() in PRIVACY_LIBRARY_ROOT_NAMES
