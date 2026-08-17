// End of file tests are purposely omitted at the moment

use std::fmt;

// Which family of executable we are holding. This decides who parses it.
#[derive(Debug, Clone)]
pub enum Format {
    Windows,
    Linux,
    Mach,
    Coff, // No DOS stub or optional header; linker yet to run
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Windows => write!(f, "Windows Executable"),
            Format::Linux => write!(f, "Linux Executable"),
            Format::Mach => write!(f, "Apple Executable (Mach-O)"),
        }
    }
}

// One function this binary borrows from somebody else's library.
// Needs at minimum: the name, and the ordinal if it was imported by number
// instead of by name.
#[derive(Clone, Debug)]
pub struct ImportFn {

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

    pub fn Width(&self) -> Option<Width> {
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

}

impl ImportFn {

}

// One library, plus every function taken out of it. Imports are the clearest
// statement a binary makes about what it intends to do, since calling into the
// OS means naming the call first.
#[derive(Debug, Clone)]
pub struct Import {

}

impl Import {

}

// One named region of the file. Described twice over: where it sits on disk
// (offset/fSize) and where it sits once mapped (address/vSize). Those two
// layouts are not the same, which is why both are recorded.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub address: u64, // virtual address
    pub vSize: u64, // virtual size
    pub offset: u64, // file offset
    pub fSize: u64, // file size
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Section {

    // Create and define readable flag
    pub fn readable(&self) -> bool {
        self.readable
    }

    // Create and define writeable flag
    pub fn writable(&self) -> bool {
        self.writable
    }

    // Create and define executable flag
    pub fn executable(&self) -> bool {
        self.executable
    }
}

// One function this binary offers out to others. Mostly a DLL concern.
// Needs: name, rva, ordinal, and the forwarder string for exports that point
// at a function in a different library rather than at code here.
#[derive(Debug, Clone)]
pub struct Export {

}

impl Export {

}

// One address that has to be patched if the image does not load at its
// preferred ImageBase. ASLR means that is the normal case now, not the
// exception.
#[derive(Debug, Clone)]
pub struct Relocation {

}

impl Relocation {

}

// Bytes past the end of the last section. No header describes this region and
// the loader never maps it, so it is the cheapest place in the file to append
// something.
#[derive(Debug, Clone)]
pub struct Overlay {
    pub offset: u64, // where undescribed region starts
    pub size: u64, // size of undescribed region
}

// The finished answer, and the reason every other type in this file exists.
// Whatever format came in, this is what comes out: one shape that report.rs
// and json.rs can read without knowing whether they are looking at a PE, an
// ELF or a Mach-O.
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