// =========================================================
// TontoJB — Kernel Offsets
// Sources: Luac0re offsets.lua, Y2JB kernel_offset.js
// =========================================================

var OFFSETS = {
    // =====================================================
    // Firmware-specific offsets (kernel data segment)
    // =====================================================
    "11.00": {
        DATA_BASE:         0x0D30000,
        ALLPROC:           0x02875D70,
        SECURITY_FLAGS:    0x00D8C064,
        ROOTVNODE:         0x030B7510,
        KERNEL_PMAP_STORE: 0x02E04F18,
        GVMSPACE:          0x02E66570,
    },
    // 11.20, 11.40, 11.60 share offsets with 11.00
    "11.20": "11.00",
    "11.40": "11.00",
    "11.60": "11.00",

    "10.00": {
        DATA_BASE:         0x0CC0000,
        ALLPROC:           0x02765D70,
        SECURITY_FLAGS:    0x00D79064,
        ROOTVNODE:         0x02FA3510,
        KERNEL_PMAP_STORE: 0x02CF0EF8,
        GVMSPACE:          0x02D52570,
    },
    "10.01": "10.00", "10.20": "10.00", "10.40": "10.00", "10.60": "10.00",

    "9.00": {
        DATA_BASE:         0x0CA0000,
        ALLPROC:           0x02755D50,
        SECURITY_FLAGS:    0x00D72064,
        ROOTVNODE:         0x02FDB510,
        KERNEL_PMAP_STORE: 0x02D28B78,
        GVMSPACE:          0x02D8A570,
    },

    "12.00": {
        DATA_BASE:         0x0D50000,
        ALLPROC:           0x02885E00,
        SECURITY_FLAGS:    0x00D83064,
        ROOTVNODE:         0x030D7510,
        KERNEL_PMAP_STORE: 0x02E1CFB8,
        GVMSPACE:          0x02E7E570,
    },
};

// =====================================================
// Struct offsets (constant across firmware versions)
// =====================================================
var STRUCT = {
    // proc
    PROC_PID:           0xBC,
    PROC_UCRED:         0x40,
    PROC_FD:            0x48,
    PROC_VM_SPACE:      0x200,

    // ucred
    UCRED_CR_UID:       0x04,
    UCRED_CR_RUID:      0x08,
    UCRED_CR_SVUID:     0x0C,
    UCRED_CR_NGROUPS:   0x10,
    UCRED_CR_RGID:      0x14,
    UCRED_CR_PRISON:    0x30,
    UCRED_CR_SCEAUTHID: 0x58,
    UCRED_CR_SCECAPS0:  0x60,
    UCRED_CR_SCECAPS1:  0x68,
    UCRED_CR_SCEATTRS:  0x83,

    // filedesc
    FILEDESC_OFILES:    0x00,
    FDESCENTTBL_HDR:    8,
    FILEDESCENT_SIZE:   0x30,

    // fd
    FD_RDIR:            0x10,
    FD_JDIR:            0x18,

    // kqueue
    KQ_FDP:             0xA8,

    // net
    INPCB_PKTOPTS:      0x120,
    IP6PO_RTHDR:        0x70,
    SO_PCB:             0x18,

    // pipe
    PIPE_SIGIO:         0xD8,

    // authid
    SYSTEM_AUTHID:      0x4800000000010003,
};

function get_fw_offsets(version) {
    var entry = OFFSETS[version];
    if (typeof entry === "string") entry = OFFSETS[entry];
    if (!entry) return null;
    var result = {};
    for (var k in entry) result[k] = entry[k];
    for (var k in STRUCT) result[k] = STRUCT[k];
    return result;
}
