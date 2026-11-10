"""Known Ordinal Databases for Windows System and Game DLLs.

Annotates ordinal-only exports with their canonical function names
(e.g. ws2_32.dll, oleaut32.dll, xlive.dll, binkw32.dll).
"""

from typing import Dict, Optional
from pathlib import Path


# WS2_32.dll standard Winsock 1.1 / 2.0 ordinal mappings
WS2_32_ORDINALS: Dict[int, str] = {
    1: "accept",
    2: "bind",
    3: "closesocket",
    4: "connect",
    5: "getpeername",
    6: "getsockname",
    7: "getsockopt",
    8: "htonl",
    9: "htons",
    10: "ioctlsocket",
    11: "inet_addr",
    12: "inet_ntoa",
    13: "listen",
    14: "ntohl",
    15: "ntohs",
    16: "recv",
    17: "recvfrom",
    18: "select",
    19: "send",
    20: "sendto",
    21: "setsockopt",
    22: "shutdown",
    23: "socket",
    101: "WSAAsyncSelect",
    102: "WSAAsyncGetHostByAddr",
    103: "WSAAsyncGetHostByName",
    104: "WSAAsyncGetProtoByNumber",
    105: "WSAAsyncGetProtoByName",
    106: "WSAAsyncGetServByPort",
    107: "WSAAsyncGetServByName",
    108: "WSACancelAsyncRequest",
    109: "WSASetBlockingHook",
    110: "WSAUnhookBlockingHook",
    111: "WSAGetLastError",
    112: "WSASetLastError",
    113: "WSACancelBlockingCall",
    114: "WSAIsBlocking",
    115: "WSAStartup",
    116: "WSACleanup",
}

# OLEAUT32.dll standard OLE Automation ordinals
OLEAUT32_ORDINALS: Dict[int, str] = {
    2: "SysAllocString",
    3: "SysReAllocString",
    4: "SysAllocStringLen",
    5: "SysReAllocStringLen",
    6: "SysFreeString",
    7: "SysStringLen",
    8: "VariantInit",
    9: "VariantClear",
    10: "VariantCopy",
    11: "VariantCopyInd",
    12: "VariantChangeType",
    13: "VariantSub",
    14: "VariantMul",
    15: "VariantDiv",
    147: "VariantChangeTypeEx",
}

# XLIVE.dll (Games for Windows Live) standard modding ordinals
XLIVE_ORDINALS: Dict[int, str] = {
    1: "XLiveInitialize",
    2: "XLiveInput",
    3: "XLiveRender",
    4: "XLiveUninitialize",
    5: "XLiveOnCreateDevice",
    6: "XLiveOnDestroyDevice",
    7: "XLiveOnResetDevice",
    8: "XHVCreateEngine",
    9: "XLivePBufferAllocate",
    10: "XLivePBufferFree",
    11: "XShowGamerCardUI",
    12: "XLiveSetSponsorToken",
    14: "XShowPlayerReviewUI",
    15: "XShowFriendsUI",
    18: "XLivePreTranslateMessage",
    20: "XLiveSetDebugLevel",
    24: "XShowMessagesUI",
    52: "XShowKeyboardUI",
    53: "XShowGamerCardUIForSummary",
    5000: "XLivePBufferAllocate_5000",
    5001: "XLivePBufferFree_5001",
    5002: "XLiveSetString_5002",
    5003: "XLiveGetString_5003",
    5005: "XLiveSetProtectedData_5005",
    5006: "XLiveGetProtectedData_5006",
    5007: "XLiveGetSession_5007",
    5008: "XLiveCloseSession_5008",
}

# BINKW32.dll (RAD Game Tools) common ordinals
BINKW32_ORDINALS: Dict[int, str] = {
    1: "BinkBufferBlit",
    2: "BinkBufferCheckForCrash",
    3: "BinkBufferClear",
    4: "BinkBufferClose",
    5: "BinkBufferGetDescription",
    6: "BinkBufferGetError",
    7: "BinkBufferLock",
    8: "BinkBufferOpen",
    9: "BinkBufferSetDirectDraw",
    10: "BinkBufferSetHWND",
    11: "BinkBufferSetResolution",
    12: "BinkBufferSetScale",
    13: "BinkBufferUnlock",
    14: "BinkCheckStatus",
    15: "BinkClose",
    16: "BinkCloseTrack",
    17: "BinkControlBackgroundIO",
    18: "BinkCopyToBuffer",
    19: "BinkDoFrame",
    20: "BinkDoFrameAsync",
    21: "BinkGetError",
    22: "BinkGetFrameBuffersInfo",
    23: "BinkGetPalette",
    24: "BinkGetRealtime",
    25: "BinkGetRects",
    26: "BinkGetSummary",
    27: "BinkGetTrackData",
    28: "BinkGetTrackID",
    29: "BinkGetTrackType",
    30: "BinkGoto",
    31: "BinkIsSoftwareCursor",
    32: "BinkLoad",
    33: "BinkLoadTrack",
    34: "BinkLogoAddress",
    35: "BinkNextFrame",
    36: "BinkOpen",
    37: "BinkOpenTrack",
    38: "BinkPause",
    39: "BinkPitch",
    40: "BinkPlaybackState",
    41: "BinkRestoreDesktop",
    42: "BinkService",
    43: "BinkSetError",
    44: "BinkSetFrameRate",
    45: "BinkSetIO",
    46: "BinkSetIOSize",
    47: "BinkSetMemory",
    48: "BinkSetMixBins",
    49: "BinkSetMixBinVolumes",
    50: "BinkSetPan",
    51: "BinkSetSimulate",
    52: "BinkSetSoundOnOff",
    53: "BinkSetSoundSystem",
    54: "BinkSetSoundTrack",
    55: "BinkSetVideoOnOff",
    56: "BinkSetVolume",
    57: "BinkStartAsyncThread",
    58: "BinkUnload",
    59: "BinkWait",
    60: "BinkWaitStop",
}

DLL_TO_ORDINAL_DB: Dict[str, Dict[int, str]] = {
    "ws2_32.dll": WS2_32_ORDINALS,
    "wsock32.dll": WS2_32_ORDINALS,
    "oleaut32.dll": OLEAUT32_ORDINALS,
    "xlive.dll": XLIVE_ORDINALS,
    "binkw32.dll": BINKW32_ORDINALS,
    "bink2w32.dll": BINKW32_ORDINALS,
    "bink2w64.dll": BINKW32_ORDINALS,
}


def lookup_known_ordinal(dll_name: str, ordinal: int) -> Optional[str]:
    """Lookup canonical function name for a known DLL ordinal.
    
    Returns the known function name if found, or None.
    """
    stem = Path(dll_name).name.lower()
    mapping = DLL_TO_ORDINAL_DB.get(stem)
    if mapping:
        return mapping.get(ordinal)
    return None
