//! CPU identification from CPUID: vendor, family, model, the hybrid flag and the SIMD level.
//!
//! The raw leaves are read once ([`read`]) and decoded by a pure function ([`decode`]), so the
//! decoding is tested with the leaves of CPUs we do not have.

/// The CPU vendor. The numbers are part of the C ABI (`HydraCpuInfo::vendor`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Vendor {
    Unknown = 0,
    Intel = 1,
    Amd = 2,
    Other = 3,
}

/// The widest SIMD level the CPU and the OS both support. The numbers are part of the C ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SimdLevel {
    /// SSE2, which every x86-64 CPU has (or not an x86-64 CPU at all).
    Baseline = 0,
    /// SSE4.2 and POPCNT.
    Sse42 = 1,
    /// AVX2 with FMA, BMI1 and BMI2 (x86-64-v3), with the YMM state saved by the OS.
    Avx2 = 2,
    /// AVX-512 F, CD, BW, DQ and VL (x86-64-v4), with the opmask and ZMM state saved by the OS.
    Avx512 = 3,
}

/// The CPUID leaves the identification needs, as `[eax, ebx, ecx, edx]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Leaves {
    pub leaf0: [u32; 4],
    pub leaf1: [u32; 4],
    /// Leaf 7, subleaf 0; zero when leaf 0 reports a maximum below 7.
    pub leaf7: [u32; 4],
    /// Leaves 0x80000002..=0x80000004 (the brand string); zero when not reported.
    pub brand: [[u32; 4]; 3],
    /// XCR0 (the state components the OS saves); zero without OSXSAVE.
    pub xcr0: u64,
}

/// What [`decode`] makes of the leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuId {
    pub vendor: Vendor,
    /// The 12-character vendor string, such as `GenuineIntel`.
    pub vendor_id: String,
    /// The display family (base family plus extended family when the base is 0xF).
    pub family: u32,
    /// The display model (extended model included for families 6 and 0xF).
    pub model: u32,
    pub stepping: u32,
    /// CPUID.07H:EDX[15], set on CPUs with more than one core type (Intel Alder Lake and later).
    pub hybrid: bool,
    pub simd: SimdLevel,
    pub brand: String,
}

impl CpuId {
    /// The identification of a CPU CPUID cannot describe (not x86-64).
    pub fn unknown() -> CpuId {
        CpuId {
            vendor: Vendor::Unknown,
            vendor_id: String::new(),
            family: 0,
            model: 0,
            stepping: 0,
            hybrid: false,
            simd: SimdLevel::Baseline,
            brand: String::new(),
        }
    }
}

const EAX: usize = 0;
const EBX: usize = 1;
const ECX: usize = 2;
const EDX: usize = 3;

fn bit(reg: u32, n: u32) -> bool {
    reg & (1 << n) != 0
}

fn bytes(regs: &[u32]) -> String {
    let raw: Vec<u8> = regs.iter().flat_map(|r| r.to_le_bytes()).collect();
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_string()
}

/// Decodes the leaves read by [`read`] (or written by a test).
pub fn decode(l: &Leaves) -> CpuId {
    let vendor_id = bytes(&[l.leaf0[EBX], l.leaf0[EDX], l.leaf0[ECX]]);
    let vendor = match vendor_id.as_str() {
        "" => Vendor::Unknown,
        "GenuineIntel" => Vendor::Intel,
        "AuthenticAMD" | "HygonGenuine" => Vendor::Amd,
        _ => Vendor::Other,
    };

    let eax = l.leaf1[EAX];
    let base_family = (eax >> 8) & 0xF;
    let base_model = (eax >> 4) & 0xF;
    let family = if base_family == 0xF {
        base_family + ((eax >> 20) & 0xFF)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xF {
        base_model | (((eax >> 16) & 0xF) << 4)
    } else {
        base_model
    };

    let ecx1 = l.leaf1[ECX];
    let ebx7 = l.leaf7[EBX];
    let ymm_saved = l.xcr0 & 0x6 == 0x6; // SSE and AVX state
    let zmm_saved = l.xcr0 & 0xE6 == 0xE6; // plus opmask, ZMM_Hi256, Hi16_ZMM
    let sse42 = bit(ecx1, 20) && bit(ecx1, 23); // SSE4.2, POPCNT
    let avx2 = sse42
        && ymm_saved
        && bit(ecx1, 28) // AVX
        && bit(ecx1, 12) // FMA
        && bit(ebx7, 5) // AVX2
        && bit(ebx7, 3) // BMI1
        && bit(ebx7, 8); // BMI2
    // AVX-512 F, DQ, CD, BW and VL
    let avx512 = avx2 && zmm_saved && [16, 17, 28, 30, 31].iter().all(|&n| bit(ebx7, n));
    let simd = if avx512 {
        SimdLevel::Avx512
    } else if avx2 {
        SimdLevel::Avx2
    } else if sse42 {
        SimdLevel::Sse42
    } else {
        SimdLevel::Baseline
    };

    CpuId {
        vendor,
        vendor_id,
        family,
        model,
        stepping: eax & 0xF,
        hybrid: bit(l.leaf7[EDX], 15),
        simd,
        brand: bytes(l.brand.as_flattened()),
    }
}

/// Reads the leaves of the CPU this runs on.
#[cfg(target_arch = "x86_64")]
pub fn read() -> Leaves {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

    #[target_feature(enable = "xsave")]
    fn xcr0() -> u64 {
        // SAFETY: called only when CPUID reports OSXSAVE, so XGETBV is enabled.
        unsafe { _xgetbv(0) }
    }

    let regs = |r: core::arch::x86_64::CpuidResult| [r.eax, r.ebx, r.ecx, r.edx];
    let mut l = Leaves {
        leaf0: regs(__cpuid(0)),
        ..Leaves::default()
    };
    if l.leaf0[EAX] >= 1 {
        l.leaf1 = regs(__cpuid(1));
    }
    if l.leaf0[EAX] >= 7 {
        l.leaf7 = regs(__cpuid_count(7, 0));
    }
    if __cpuid(0x8000_0000).eax >= 0x8000_0004 {
        for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            l.brand[i] = regs(__cpuid(leaf));
        }
    }
    if bit(l.leaf1[ECX], 27) {
        // SAFETY: the xsave target feature is only needed for XGETBV, which OSXSAVE enables.
        l.xcr0 = unsafe { xcr0() };
    }
    l
}

/// Identifies the CPU this runs on.
pub fn identify() -> CpuId {
    #[cfg(target_arch = "x86_64")]
    {
        decode(&read())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        CpuId::unknown()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn vendor(s: &str) -> [u32; 4] {
        let b = s.as_bytes();
        let w = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        [0x20, w(0), w(8), w(4)]
    }

    fn brand(s: &str) -> [[u32; 4]; 3] {
        let mut raw = [0u8; 48];
        raw[..s.len()].copy_from_slice(s.as_bytes());
        let mut out = [[0u32; 4]; 3];
        for (i, chunk) in raw.chunks(4).enumerate() {
            out[i / 4][i % 4] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        out
    }

    /// The leaves of an i7-13700KF (family 6, model 0xB7, stepping 1): hybrid, AVX2, no AVX-512.
    pub(crate) fn raptor_lake_13700kf() -> Leaves {
        Leaves {
            leaf0: vendor("GenuineIntel"),
            leaf1: [0x000B_0671, 0, 0x7FFA_FBFF, 0xBFEB_FBFF],
            leaf7: [0, 0x239C_27EB, 0x1840_0124, 0xFC1C_C410],
            brand: brand("13th Gen Intel(R) Core(TM) i7-13700KF"),
            xcr0: 0x207,
        }
    }

    /// The leaves of a Ryzen 9 7950X (family 0x19, model 0x61): AVX-512, not hybrid.
    pub(crate) fn zen4_7950x() -> Leaves {
        Leaves {
            leaf0: vendor("AuthenticAMD"),
            leaf1: [0x00A6_0F12, 0, 0x7EF8_320B, 0x178B_FBFF],
            leaf7: [1, 0xF1BF_97A9, 0x0040_5FCE, 0x1000_0010],
            brand: brand("AMD Ryzen 9 7950X 16-Core Processor"),
            xcr0: 0x2E7,
        }
    }

    #[test]
    fn decodes_raptor_lake() {
        let id = decode(&raptor_lake_13700kf());
        assert_eq!(id.vendor, Vendor::Intel);
        assert_eq!(id.vendor_id, "GenuineIntel");
        assert_eq!((id.family, id.model, id.stepping), (6, 0xB7, 1));
        assert!(id.hybrid);
        assert_eq!(id.simd, SimdLevel::Avx2);
        assert_eq!(id.brand, "13th Gen Intel(R) Core(TM) i7-13700KF");
    }

    #[test]
    fn decodes_zen4_with_extended_family() {
        let id = decode(&zen4_7950x());
        assert_eq!(id.vendor, Vendor::Amd);
        assert_eq!((id.family, id.model, id.stepping), (0x19, 0x61, 2));
        assert!(!id.hybrid);
        assert_eq!(id.simd, SimdLevel::Avx512);
    }

    #[test]
    fn simd_needs_the_os_to_save_the_state() {
        // AVX-512 hardware under an OS that saves only the YMM state: AVX2.
        let mut l = zen4_7950x();
        l.xcr0 = 0x7;
        assert_eq!(decode(&l).simd, SimdLevel::Avx2);
        // No OSXSAVE at all: SSE4.2.
        l.xcr0 = 0;
        assert_eq!(decode(&l).simd, SimdLevel::Sse42);
    }

    #[test]
    fn unknown_vendor_and_empty_leaves() {
        let id = decode(&Leaves::default());
        assert_eq!(id.vendor, Vendor::Unknown);
        assert_eq!(id.simd, SimdLevel::Baseline);
        let l = Leaves {
            leaf0: vendor("CentaurHauls"),
            ..Leaves::default()
        };
        assert_eq!(decode(&l).vendor, Vendor::Other);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn reads_this_cpu() {
        // Whatever this CPU is, x86-64 has SSE2 and CPUID names a vendor; the SIMD level agrees
        // with what the standard library detects.
        let id = identify();
        assert_ne!(id.vendor, Vendor::Unknown);
        assert_eq!(
            id.simd >= SimdLevel::Avx2,
            std::is_x86_feature_detected!("avx2")
        );
        assert_eq!(
            id.simd >= SimdLevel::Sse42,
            std::is_x86_feature_detected!("sse4.2")
        );
    }
}
