// End of file tests are purposely omitted at the moment

use std::fmt;

// Which family of executable we are holding. This decides who parses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Executable,
    Elf,
    MachO,
    // No top-level coff support; exists only to be refeused as ParseError::UnsupportedFormat
    Coff, // No DOS stub or optional header; linker yet to run
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Executable => write!(f, "Portable Executable"),
            Format::Elf => write!(f, "Unix/Linux"),
            Format::MachO => write!(f, "Mach-O (Apple iOS/Mac)"),
            Format::Coff => write!(f, "Top-Level COFF; Unsupported"),
        }
    }
}

// Where the loader writes the function's real address once it is resolved
#[derive(Clone, Debug)]
pub struct ImportFn {
    pub name: String,
    pub iat_rva: Option<u64>,
    // Sometimes, it's imported by number not name. Pesky malware authors
    pub ordinal: Option<u16>,
}

impl ImportFn {

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Bits32,
    Bits64,
}

impl Width {
    pub fn bits(self) -> u8 {
        match self {
            Width::Bits32 => 32,
            Width::Bits64 => 64,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86(Width),
    Arm(Width),
    Mips(Width),
    Unknown(u32),
}

impl Architecture {
    pub fn pe(machine: u16) -> Self {
        match machine {
            0x014C => Architecture::X86(Width::Bits32),
            0x8664 => Architecture::X86(Width::Bits64),

            0x01C0 | 0x01C4 => Architecture::Arm(Width::Bits32),
            0xAA64 => Architecture::Arm(Width::Bits64),

            0x0162 | 0x0166 | 0x0168 | 0x0169 => Architecture::Mips(Width::Bits32),

            other => Architecture::Unknown(other as u32),
        }
    }

    pub fn elf(e_machine: u16, class64: bool) -> Self {
        let w = if class64 {Width::Bits64} else {Width::Bits32};

        match e_machine {
            0x03 => Architecture::X86(Width::Bits32),
            0x3E => Architecture::X86(Width::Bits64),

            0x28 => Architecture::Arm(Width::Bits32),
            0xB7 => Architecture::Arm(Width::Bits64),

            // Cannot alone tell the width
            0x08 => Architecture::Mips(w),

            other => Architecture::Unknown(other as u32),
        }
    }

    /*
        Apple restricts its modern operating systems to ARM64.
        Quite a few older apple products still run x86-x64 architectures.
        There was, once upon a time, MIPS for Mach-O but has long been dropped.
        You'll find a legacy header for this, but is not used at all.
    */

    pub fn mac(cputype: u32) -> Self {
        const ABI64: u32 = 0x0100_0000;

        let w = if cputype & ABI64 != 0 {Width::Bits64} else {Width::Bits32};

        match cputype & !ABI64 {
            0x07 => Architecture::X86(w),
            0x0C => Architecture::Arm(w),
            _ => Architecture::Unknown(cputype),
        }
    }

    pub fn width(&self) -> Option<Width> {
        match self {
            Architecture::X86(w) |
            Architecture::Arm(w) |
            Architecture::Mips(w) => Some(*w),
            Architecture::Unknown(_) => None,
        }
    }

    pub fn bits(&self) -> Option<u8> {
        self.width().map(|w| w.bits())
    }

    pub fn family(&self) -> &'static str {
        match self {
            Architecture::X86(_) => "x86",
            Architecture::Arm(_) => "ARM",
            Architecture::Mips(_) => "MIPS",
            Architecture::Unknown(_) => "Unknown Architecture",
        }
    }

    pub fn supported(&self) -> bool {
        matches!(self, Architecture::X86(_) | Architecture::Arm(_))
    }

}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Architecture::X86(Width::Bits32) => f.write_str("x86"),
            Architecture::X86(Width::Bits64) => f.write_str("x86-x64"),
            Architecture::Arm(Width::Bits32) => f.write_str("ARM32"),
            Architecture::Arm(Width::Bits64) => f.write_str("AArch64"),
            Architecture::Mips(Width::Bits32) => f.write_str("MIPS32"),
            Architecture::Mips(Width::Bits64) => f.write_str("MIPS64"),
            Architecture::Unknown(raw) => write!(f, "Unknown ({raw:#x})"),
        }
    }
}

// One library, plus every function taken out of it. Imports are the clearest
// statement a binary makes about what it intends to do, since calling into the
// OS means naming the call first.
#[derive(Debug, Clone)]
pub struct Import {
    pub library: String,
    pub functions: Vec<ImportFn>, // Gets all addresses of all imported functions
}

impl Import {
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.functions.iter().map(|f| f.name.as_str())
    }
}

// One named region of the file. Described twice over: where it sits on disk
// (offset/fSize) and where it sits once mapped (address/vSize). Those two
// layouts are not the same, which is why both are recorded.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64, // virtual address
    pub virtual_size: u64, // virtual size
    pub file_offset: u64, // file offset
    pub file_size: u64, // file size
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub entropy: f64, 
}

impl Section {

    pub const HIGH_ENTROPY: f64 = 7.0;

    // Create readable flag
    pub fn readable(&self) -> bool {
        self.readable
    }

    // Create writeable flag
    pub fn writable(&self) -> bool {
        self.writable
    }

    // Create executable flag
    pub fn executable(&self) -> bool {
        self.executable
    }

    // Redundant probably. 
    pub fn write_executeable(&self) -> bool {
        self.writable && self.executable
    }

    // High Entropy
    pub fn high_entropy(&self) -> bool {
        self.entropy >= Self::HIGH_ENTROPY
    }

    // Packed or Encrypted, doesn't matter. They look the same
    pub fn packed_encrypted(&self) -> bool {
        self.executable && self.high_entropy()
    }

    // Section bytes on the disk.
    pub fn disk_bytes<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        clamped_slice(file, self.offset, self.file_size)
    }

}

// Not all that common you'd export a function from an executable, but you can.
// This mainly covers DLL's (Dynamic-Link Libraries), which often export functions.
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub rva: u64,
    pub ordinal: u16,
    pub forwarder: Option<String>,
}

impl Export {

}

// One address that has to be patched
#[derive(Debug, Clone)]
pub struct Relocation {
    pub rva: u64,
    pub kind: u16,
}

impl Relocation {

}

// Bytes past the end of the last section.
#[derive(Debug, Clone)]
pub struct Overlay {
    pub offset: u64, // where undescribed region starts
    pub size: u64, // size of undescribed region
    pub entropy: f64,
}

#[derive(Debug, Clone)]
pub struct ExeMeta {
    pub timestamp: u32,
    pub reproducible: bool,
    pub subsystem: &'static str,
    pub dll_characteristics: Vec<&'static str>,
    pub dotnet: bool,
    pub signed: bool,
    pub resources: bool,
    pub tls_callbacks: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub format: Format,
    pub arch: Architecture,
    pub bytes: Vec<u8>,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub strings: Vec<String>, 
    pub relocations: Vec<Relocation>,
    pub overlay: Option<Overlay>,
}

impl Binary {

}