use std::fmt;

pub type ParseResult<T> = Result<T, ParseError>;

/// How much the finding should alarm the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Structure is fine, noted for completeness.
    Info,
    /// Per spec, but unusual in benign software.
    Notable,
    /// Violates the spec, or is self-contradictory. Toolchains do not emit this.
    Malformed,
    /// Strongly associated with deliberate tampering / anti-analysis.
    Suspicious,
    /// Parsing cannot continue.
    Fatal,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Notable => "notable",
            Severity::Malformed => "malformed",
            Severity::Suspicious => "suspicious",
            Severity::Fatal => "fatal",
        };
        f.write_str(s)
    }
}

/// Which container the error came from, for messages that are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Coff,
    Unknown,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
            Format::Coff => "COFF",
            Format::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq,)]
pub enum ParseError {

    /// Zero-length input.
    Empty,

    /// Fewer bytes than the smallest possible header for any known format.
    TooSmall { have: usize, need: usize },

    /// Exceeds the configured read budget (see limits.rs). Refuse rather
    /// than let a crafted size field drive an allocation.
    FileTooLarge { size: u64, limit: u64 },

    /// Read failure from the OS. io::Error is not Clone, so it is flattened.
    Io { kind: std::io::ErrorKind, msg: String },

    /// Nothing at offset 0 matched a known container.
    UnknownFormat { magic: [u8; 8] },

    /// More than one container claims the file (polyglot / chimera).
    /// e.g. valid ELF magic at 0 and a valid PE at e_lfanew.
    AmbiguousFormat { candidates: &'static [&'static str] },

    /// Recognised, but this build cannot represent it.
    UnsupportedFormat { format: Format, detail: &'static str },

    /// MZ present, but e_lfanew points at a pre-PE header: NE, LE, LX, or a
    /// DOS-only stub. Runs on Windows, but not as a PE.
    LegacyExecutable { kind: &'static str, offset: u64 },

    /// Container magic wrong. This is the `MZ` / `\x7fELF` / feedface check.
    BadMagic {
        format: Format,
        offset: u64,
        expected: u32,
        found: u32,
    },

    /// The magic bytes are absent or corrupted but intact
    StrippedMagic {
        format: Format,
        offset: u64,
        found: u32,
        /// Offset of the intact downstream header that proves intent.
        intact_header_at: u64,
    },

    /// PE\0\0 (or the equivalent per-format secondary signature) wrong.
    BadSignature {
        format: Format,
        offset: u64,
        expected: u32,
        found: u32,
    },

    /// Byte order / class byte is not one of the defined values.
    UnknownEndianness { offset: u64, found: u8 },
    UnknownClass { offset: u64, found: u8 },

    /// Machine/architecture field is not a value we know.
    UnknownMachine { found: u16 },

    /// Recognised architecture, but the parser has no support for it.
    UnsupportedMachine { machine: u16, name: &'static str },

    /// A structure runs past EOF.
    OutOfBounds {
        what: &'static str,
        offset: u64,
        size: u64,
        file_size: u64,
    },

    /// A header ends past EOF partway through.
    TruncatedHeader {
        what: &'static str,
        offset: u64,
        need: usize,
        have: usize,
    },

    /// A table declares more entries than the remaining file can hold.
    TruncatedTable {
        what: &'static str,
        declared: u64,
        available: u64,
    },

    /// offset + size wrapped. Classic parser-crash bait.
    IntegerOverflow {
        what: &'static str,
        offset: u64,
        size: u64,
    },

    /// A count/size field that must be non-zero was zero.
    ZeroSize { what: &'static str, offset: u64 },

    /// Offset violates the alignment the spec requires for that field.
    Misaligned {
        what: &'static str,
        offset: u64,
        required: u64,
    },

    /// A structure points backwards into a region already consumed, or into
    /// its own header. Used for e_lfanew < size_of::<DosHeader>().
    OverlappingStructure {
        what: &'static str,
        offset: u64,
        collides_with: &'static str,
    },

    /// e_lfanew is negative, past EOF, misaligned, or inside the DOS header.
    BadLfanew { value: i32, file_size: u64 },

    /// Optional header magic is neither 0x10B (PE32) nor 0x20B (PE32+).
    BadOptionalMagic { offset: u64, found: u16 },

    /// SizeOfOptionalHeader disagrees with the magic's fixed layout.
    /// Under-sizing it truncates the data directory; over-sizing hides bytes.
    OptionalHeaderSizeMismatch {
        declared: u16,
        expected: u16,
        magic: u16,
    },

    /// PE32+ optional header on a 32-bit machine, or the reverse.
    MachineClassMismatch { machine: u16, magic: u16 },

    /// NumberOfSections is 0, or above the loader's hard cap of 96.
    BadSectionCount { count: u32, max: u32 },

    /// NumberOfRvaAndSizes is not 16 and not a value the loader tolerates.
    BadDataDirectoryCount { count: u32 },

    /// SizeOfHeaders is smaller than the headers actually parsed, or is not a
    /// multiple of FileAlignment.
    BadSizeOfHeaders { declared: u64, actual: u64 },

    /// FileAlignment/SectionAlignment are not powers of two in range, or
    /// SectionAlignment < FileAlignment.
    BadAlignment {
        file_alignment: u32,
        section_alignment: u32,
    },

    /// SizeOfImage is not a multiple of SectionAlignment, or does not cover
    /// the highest section.
    BadSizeOfImage { declared: u64, required: u64 },

    /// ImageBase is misaligned or out of range for the class.
    BadImageBase { value: u64 },

    /// PointerToRawData + SizeOfRawData exceeds EOF.
    SectionOutOfFile {
        name: String,
        index: usize,
        offset: u64,
        size: u64,
        file_size: u64,
    },

    /// VirtualAddress + VirtualSize exceeds SizeOfImage.
    SectionOutOfImage {
        name: String,
        index: usize,
        rva: u64,
        size: u64,
        image_size: u64,
    },

    /// Two sections claim the same virtual range. The loader maps them in
    /// order, so this is used to hide code from static parsers.
    SectionOverlap {
        a: String,
        b: String,
        rva: u64,
    },

    /// Section table is not sorted by VirtualAddress, or leaves a gap the
    /// loader will not map.
    SectionOrdering { name: String, index: usize },

    /// Section headers collide with the region SizeOfHeaders reserves.
    SectionInHeaders { name: String, index: usize },

    /// A section name that is not NUL-terminated and not 8 printable bytes,
    /// or a /nn string-table reference that does not resolve.
    BadSectionName { index: usize, raw: [u8; 8] },

    /// An RVA does not fall inside any section, so it cannot be translated
    /// to a file offset.
    RvaNotMapped { what: &'static str, rva: u64 },

    /// The RVA maps into a section whose raw data is smaller than the
    /// virtual span, so the target only exists at runtime.
    RvaInUninitializedData { what: &'static str, rva: u64 },

    /// AddressOfEntryPoint is 0 for an image that is not a DLL, or lies
    /// outside every section.
    BadEntryPoint { rva: u64, image_size: u64 },

    /// A data directory entry's RVA/size pair is inconsistent or unmapped.
    BadDataDirectory {
        index: usize,
        name: &'static str,
        rva: u64,
        size: u64,
    },

    /// Import descriptor array is not NUL-terminated before EOF.
    UnterminatedImportTable { offset: u64 },

    /// A thunk/descriptor chain points at itself or forms a cycle.
    CircularReference { what: &'static str, offset: u64 },

    /// An import name/DLL name is unterminated, empty, or non-ASCII.
    BadImportName { descriptor: usize, offset: u64 },

    /// Import by ordinal with an ordinal outside the target's export range.
    BadOrdinal { dll: String, ordinal: u16 },

    /// Export directory's name/ordinal/address array lengths disagree.
    ExportTableMismatch {
        names: u32,
        ordinals: u32,
        functions: u32,
    },

    /// A forwarder string is malformed (no `.`, unterminated).
    BadForwarder { offset: u64 },

    /// Relocation block size is 0, not a multiple of 2, or overruns the dir.
    BadRelocationBlock { offset: u64, size: u32 },

    /// Relocation type is not defined for this machine.
    UnknownRelocationType { offset: u64, kind: u16 },

    /// Resource directory nests deeper than the format permits, or a node
    /// points back up the tree.
    BadResourceTree { offset: u64, depth: usize },

    /// TLS directory callback array is unmapped or unterminated.
    BadTlsDirectory { rva: u64 },

    /// Debug directory entry points outside the file.
    BadDebugDirectory { index: usize, offset: u64 },

    /// Authenticode: WIN_CERTIFICATE header is malformed, or the certificate
    /// table extends past EOF.
    BadCertificateTable { offset: u64, size: u64 },

    /// Symbol/string table offset or count is unusable.
    BadSymbolTable { offset: u64, count: u32 },

    /// A string field is not valid UTF-8 / not valid for its declared codepage.
    InvalidEncoding { what: &'static str, offset: u64 },

    /// A NUL-terminated string ran to EOF without a terminator.
    UnterminatedString { what: &'static str, offset: u64 },

    // Self-defence. A hostile file will try to make the parser the victim.
    /// Recursion cap hit (nested resources, fat binary members, forwarders).
    RecursionLimit { what: &'static str, depth: usize },

    /// A table declared more entries than limits.rs permits.
    LimitExceeded {
        what: &'static str,
        count: u64,
        limit: u64,
    },

    /// The parser looped without consuming input.
    NoProgress { what: &'static str, offset: u64 },

    /// A structure is internally inconsistent in a way with no dedicated
    /// variant yet.
    InvalidObject { what: &'static str, detail: String },
}

impl ParseError {
    /// Stable identifier for machine-readable output (json.rs) and for
    /// grepping a corpus. Do not renumber these once published.
    pub fn code(&self) -> &'static str {
        use ParseError::*;
        match self {
            Empty => "IN-001",
            TooSmall { .. } => "IN-002",
            FileTooLarge { .. } => "IN-003",
            Io { .. } => "IN-004",

            UnknownFormat { .. } => "FMT-001",
            AmbiguousFormat { .. } => "FMT-002",
            UnsupportedFormat { .. } => "FMT-003",
            LegacyExecutable { .. } => "FMT-004",
            BadMagic { .. } => "FMT-005",
            StrippedMagic { .. } => "FMT-006",
            BadSignature { .. } => "FMT-007",
            UnknownEndianness { .. } => "FMT-008",
            UnknownClass { .. } => "FMT-009",
            UnknownMachine { .. } => "FMT-010",
            UnsupportedMachine { .. } => "FMT-011",

            OutOfBounds { .. } => "BND-001",
            TruncatedHeader { .. } => "BND-002",
            TruncatedTable { .. } => "BND-003",
            IntegerOverflow { .. } => "BND-004",
            ZeroSize { .. } => "BND-005",
            Misaligned { .. } => "BND-006",
            OverlappingStructure { .. } => "BND-007",

            BadLfanew { .. } => "HDR-001",
            BadOptionalMagic { .. } => "HDR-002",
            OptionalHeaderSizeMismatch { .. } => "HDR-003",
            MachineClassMismatch { .. } => "HDR-004",
            BadSectionCount { .. } => "HDR-005",
            BadDataDirectoryCount { .. } => "HDR-006",
            BadSizeOfHeaders { .. } => "HDR-007",
            BadAlignment { .. } => "HDR-008",
            BadSizeOfImage { .. } => "HDR-009",
            BadImageBase { .. } => "HDR-010",

            SectionOutOfFile { .. } => "SEC-001",
            SectionOutOfImage { .. } => "SEC-002",
            SectionOverlap { .. } => "SEC-003",
            SectionOrdering { .. } => "SEC-004",
            SectionInHeaders { .. } => "SEC-005",
            BadSectionName { .. } => "SEC-006",

            RvaNotMapped { .. } => "ADR-001",
            RvaInUninitializedData { .. } => "ADR-002",
            BadEntryPoint { .. } => "ADR-003",

            BadDataDirectory { .. } => "TAB-001",
            UnterminatedImportTable { .. } => "TAB-002",
            CircularReference { .. } => "TAB-003",
            BadImportName { .. } => "TAB-004",
            BadOrdinal { .. } => "TAB-005",
            ExportTableMismatch { .. } => "TAB-006",
            BadForwarder { .. } => "TAB-007",
            BadRelocationBlock { .. } => "TAB-008",
            UnknownRelocationType { .. } => "TAB-009",
            BadResourceTree { .. } => "TAB-010",
            BadTlsDirectory { .. } => "TAB-011",
            BadDebugDirectory { .. } => "TAB-012",
            BadCertificateTable { .. } => "TAB-013",
            BadSymbolTable { .. } => "TAB-014",

            InvalidEncoding { .. } => "ENC-001",
            UnterminatedString { .. } => "ENC-002",

            RecursionLimit { .. } => "LIM-001",
            LimitExceeded { .. } => "LIM-002",
            NoProgress { .. } => "LIM-003",

            InvalidObject { .. } => "GEN-001",
        }
    }

    /// File offset the error points at, when one is known. Lets report.rs
    /// hand the analyst a hexdump window without a second lookup.
    pub fn offset(&self) -> Option<u64> {
        use ParseError::*;
        match self {
            BadMagic { offset, .. }
            | StrippedMagic { offset, .. }
            | BadSignature { offset, .. }
            | LegacyExecutable { offset, .. }
            | UnknownEndianness { offset, .. }
            | UnknownClass { offset, .. }
            | OutOfBounds { offset, .. }
            | TruncatedHeader { offset, .. }
            | IntegerOverflow { offset, .. }
            | ZeroSize { offset, .. }
            | Misaligned { offset, .. }
            | OverlappingStructure { offset, .. }
            | BadOptionalMagic { offset, .. }
            | SectionOutOfFile { offset, .. }
            | UnterminatedImportTable { offset }
            | CircularReference { offset, .. }
            | BadImportName { offset, .. }
            | BadForwarder { offset }
            | BadRelocationBlock { offset, .. }
            | UnknownRelocationType { offset, .. }
            | BadResourceTree { offset, .. }
            | BadDebugDirectory { offset, .. }
            | BadCertificateTable { offset, .. }
            | BadSymbolTable { offset, .. }
            | InvalidEncoding { offset, .. }
            | UnterminatedString { offset, .. }
            | NoProgress { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    /// Everything here stops a parse, but some variants additionally mean
    /// "someone did this on purpose". Those get promoted in the summary.
    pub fn severity(&self) -> Severity {
        use ParseError::*;
        match self {
            // Boring: the file is just not what we were given to expect.
            Empty | TooSmall { .. } | Io { .. } | UnknownFormat { .. } => Severity::Fatal,
            UnsupportedFormat { .. } | UnsupportedMachine { .. } | LegacyExecutable { .. } => {
                Severity::Notable
            }

            // Deliberate-tampering signals.
            StrippedMagic { .. }
            | AmbiguousFormat { .. }
            | SectionOverlap { .. }
            | OverlappingStructure { .. }
            | IntegerOverflow { .. }
            | CircularReference { .. }
            | RecursionLimit { .. }
            | LimitExceeded { .. }
            | NoProgress { .. }
            | FileTooLarge { .. } => Severity::Suspicious,

            _ => Severity::Fatal,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseError::*;
        match self {
            Empty => write!(f, "input is empty"),
            TooSmall { have, need } => {
                write!(f, "input is {have} bytes, need at least {need}")
            }
            FileTooLarge { size, limit } => {
                write!(f, "input is {size} bytes, exceeds limit of {limit}")
            }
            Io { kind, msg } => write!(f, "i/o error ({kind:?}): {msg}"),

            UnknownFormat { magic } => {
                write!(f, "no known container magic at 0x0 (first bytes: ")?;
                for b in magic {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
            AmbiguousFormat { candidates } => {
                write!(f, "file matches multiple containers ({}) - polyglot", candidates.join(", "))
            }
            UnsupportedFormat { format, detail } => {
                write!(f, "{format} recognised but unsupported: {detail}")
            }
            LegacyExecutable { kind, offset } => {
                write!(f, "MZ header points to a {kind} executable at {offset:#x}, not PE")
            }
            BadMagic { format, offset, expected, found } => {
                write!(
                    f,
                    "{format} magic at {offset:#x} is {found:#06x}, expected {expected:#06x}"
                )
            }
            StrippedMagic { format, offset, found, intact_header_at } => {
                write!(
                    f,
                    "{format} magic at {offset:#x} is {found:#06x} (zeroed/replaced) but an \
                     intact header follows at {intact_header_at:#x} - header stripped for a \
                     custom loader"
                )
            }
            BadSignature { format, offset, expected, found } => {
                write!(
                    f,
                    "{format} signature at {offset:#x} is {found:#010x}, expected {expected:#010x}"
                )
            }
            UnknownEndianness { offset, found } => {
                write!(f, "unknown endianness byte {found:#04x} at {offset:#x}")
            }
            UnknownClass { offset, found } => {
                write!(f, "unknown class byte {found:#04x} at {offset:#x}")
            }
            UnknownMachine { found } => write!(f, "unknown machine type {found:#06x}"),
            UnsupportedMachine { machine, name } => {
                write!(f, "unsupported machine {name} ({machine:#06x})")
            }

            OutOfBounds { what, offset, size, file_size } => {
                write!(
                    f,
                    "{what} at {offset:#x} spans {size} bytes, past EOF ({file_size} bytes)"
                )
            }
            TruncatedHeader { what, offset, need, have } => {
                write!(f, "{what} at {offset:#x} truncated: need {need} bytes, have {have}")
            }
            TruncatedTable { what, declared, available } => {
                write!(f, "{what} declares {declared} entries, only {available} fit in the file")
            }
            IntegerOverflow { what, offset, size } => {
                write!(f, "{what}: offset {offset:#x} + size {size:#x} overflows")
            }
            ZeroSize { what, offset } => write!(f, "{what} at {offset:#x} has zero size"),
            Misaligned { what, offset, required } => {
                write!(f, "{what} at {offset:#x} is not {required}-byte aligned")
            }
            OverlappingStructure { what, offset, collides_with } => {
                write!(f, "{what} at {offset:#x} overlaps {collides_with}")
            }

            BadLfanew { value, file_size } => {
                write!(f, "e_lfanew {value:#x} is out of range for a {file_size}-byte file")
            }
            BadOptionalMagic { offset, found } => {
                write!(
                    f,
                    "optional header magic {found:#06x} at {offset:#x}, expected 0x010b or 0x020b"
                )
            }
            OptionalHeaderSizeMismatch { declared, expected, magic } => {
                write!(
                    f,
                    "SizeOfOptionalHeader is {declared}, expected {expected} for magic {magic:#06x}"
                )
            }
            MachineClassMismatch { machine, magic } => {
                write!(f, "machine {machine:#06x} contradicts optional header magic {magic:#06x}")
            }
            BadSectionCount { count, max } => {
                write!(f, "NumberOfSections is {count}, limit is {max}")
            }
            BadDataDirectoryCount { count } => {
                write!(f, "NumberOfRvaAndSizes is {count}, expected 16")
            }
            BadSizeOfHeaders { declared, actual } => {
                write!(f, "SizeOfHeaders is {declared:#x}, headers actually occupy {actual:#x}")
            }
            BadAlignment { file_alignment, section_alignment } => {
                write!(
                    f,
                    "invalid alignment: FileAlignment {file_alignment:#x}, \
                     SectionAlignment {section_alignment:#x}"
                )
            }
            BadSizeOfImage { declared, required } => {
                write!(f, "SizeOfImage is {declared:#x}, sections require {required:#x}")
            }
            BadImageBase { value } => write!(f, "invalid ImageBase {value:#x}"),

            SectionOutOfFile { name, index, offset, size, file_size } => {
                write!(
                    f,
                    "section {index} ({name}) raw data {offset:#x}+{size:#x} exceeds \
                     file size {file_size:#x}"
                )
            }
            SectionOutOfImage { name, index, rva, size, image_size } => {
                write!(
                    f,
                    "section {index} ({name}) virtual range {rva:#x}+{size:#x} exceeds \
                     SizeOfImage {image_size:#x}"
                )
            }
            SectionOverlap { a, b, rva } => {
                write!(f, "sections {a} and {b} both map {rva:#x}")
            }
            SectionOrdering { name, index } => {
                write!(f, "section {index} ({name}) is out of virtual address order")
            }
            SectionInHeaders { name, index } => {
                write!(f, "section {index} ({name}) starts inside the header region")
            }
            BadSectionName { index, raw } => {
                write!(f, "section {index} has an unreadable name (")?;
                for b in raw {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }

            RvaNotMapped { what, rva } => {
                write!(f, "{what} RVA {rva:#x} is not covered by any section")
            }
            RvaInUninitializedData { what, rva } => {
                write!(f, "{what} RVA {rva:#x} resolves to uninitialized data, no file bytes")
            }
            BadEntryPoint { rva, image_size } => {
                write!(f, "entry point {rva:#x} is outside the image ({image_size:#x})")
            }

            BadDataDirectory { index, name, rva, size } => {
                write!(f, "data directory {index} ({name}) invalid: rva {rva:#x}, size {size:#x}")
            }
            UnterminatedImportTable { offset } => {
                write!(f, "import descriptor array at {offset:#x} is not terminated")
            }
            CircularReference { what, offset } => {
                write!(f, "{what} at {offset:#x} forms a cycle")
            }
            BadImportName { descriptor, offset } => {
                write!(f, "import descriptor {descriptor} has an invalid name at {offset:#x}")
            }
            BadOrdinal { dll, ordinal } => {
                write!(f, "import {dll}#{ordinal} has an out-of-range ordinal")
            }
            ExportTableMismatch { names, ordinals, functions } => {
                write!(
                    f,
                    "export table inconsistent: {names} names, {ordinals} ordinals, \
                     {functions} functions"
                )
            }
            BadForwarder { offset } => write!(f, "malformed export forwarder at {offset:#x}"),
            BadRelocationBlock { offset, size } => {
                write!(f, "relocation block at {offset:#x} has invalid size {size:#x}")
            }
            UnknownRelocationType { offset, kind } => {
                write!(f, "unknown relocation type {kind} at {offset:#x}")
            }
            BadResourceTree { offset, depth } => {
                write!(f, "malformed resource tree at {offset:#x} (depth {depth})")
            }
            BadTlsDirectory { rva } => write!(f, "malformed TLS directory at rva {rva:#x}"),
            BadDebugDirectory { index, offset } => {
                write!(f, "debug directory entry {index} at {offset:#x} is invalid")
            }
            BadCertificateTable { offset, size } => {
                write!(f, "certificate table at {offset:#x} (size {size:#x}) is malformed")
            }
            BadSymbolTable { offset, count } => {
                write!(f, "symbol table at {offset:#x} with {count} entries is unusable")
            }

            InvalidEncoding { what, offset } => {
                write!(f, "{what} at {offset:#x} is not valid text")
            }
            UnterminatedString { what, offset } => {
                write!(f, "{what} at {offset:#x} has no terminator before EOF")
            }

            RecursionLimit { what, depth } => {
                write!(f, "{what} exceeded recursion limit at depth {depth}")
            }
            LimitExceeded { what, count, limit } => {
                write!(f, "{what} declares {count} entries, limit is {limit}")
            }
            NoProgress { what, offset } => {
                write!(f, "{what} made no progress at {offset:#x}")
            }

            InvalidObject { what, detail } => write!(f, "invalid {what}: {detail}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io {
            kind: e.kind(),
            msg: e.to_string(),
        }
    }
} 

#[derive(Debug, Clone)]
pub enum Anomaly {
    /// Bytes not claimed by any section or header. Appended payloads,
    /// installer archives, and Authenticode blobs all live here.
    Overlay { offset: u64, size: u64, entropy: f64 },

    /// Gaps between sections large enough to hide a payload.
    SlackSpace { after: String, offset: u64, size: u64 },

    /// Raw size far exceeds virtual size (or the reverse), which is how
    /// unpacking stubs reserve room for the decompressed image.
    SectionSizeMismatch { name: String, raw: u64, virt: u64 },

    /// Section is writable and executable. Almost never emitted by a
    /// legitimate toolchain; near-universal in packed samples.
    WritableExecutableSection { name: String },

    /// Section is executable but not named like code, or vice versa.
    UnexpectedSectionPermissions { name: String, characteristics: u32 },

    /// Section name is not a known toolchain name (.text/.data/.rdata/...).
    /// Carries the packer name when recognised: UPX0, .aspack, .themida.
    UnusualSectionName { name: String, known_packer: Option<String> },

    /// Duplicate section names.
    DuplicateSectionName { name: String, count: usize },

    // ---- Entropy / packing ----
    /// Section entropy above the compressed/encrypted threshold.
    HighEntropySection { name: String, entropy: f64 },

    /// Whole-file entropy suggests packing.
    HighEntropyFile { entropy: f64 },

    /// Entropy near zero across a large span: padding, or a wiped region.
    ZeroFilledRegion { offset: u64, size: u64 },

    // ---- Entry point ----
    /// Entry point is not in the first executable section.
    EntryPointOutsideCode { rva: u64, section: Option<String> },

    /// Entry point lands in a writable section.
    EntryPointInWritableSection { rva: u64, section: String },

    /// Entry point is in the last section, the classic packer stub position.
    EntryPointInLastSection { rva: u64, section: String },

    /// Entry point sits in the header region or the overlay.
    EntryPointOutsideSections { rva: u64 },

    // ---- Imports ----
    /// Very few imports for the file size: resolved dynamically at runtime.
    SparseImportTable { count: usize },

    /// No import table at all.
    NoImports,

    /// Imports only the runtime-resolution primitives.
    DynamicResolutionOnly { functions: Vec<String> },

    /// Imports associated with injection, hooking, or anti-analysis.
    /// The list belongs in a data table, not here; this just carries it.
    SuspiciousImport { dll: String, function: String, reason: &'static str },

    /// Import table lies outside the sections it should be in, or is
    /// bound/delay-loaded in an unusual configuration.
    IrregularImportLayout { rva: u64, detail: &'static str },

    // ---- Toolchain fingerprints (see the Rich header discussion) ----
    /// Rich header absent from an MSVC-linked binary, or present but with a
    /// bad checksum. Zeroing it is a deliberate anti-attribution step.
    RichHeaderAnomaly { detail: &'static str },

    /// Rich header contents contradict the linker version in the optional
    /// header. Used for false-flagging.
    RichHeaderMismatch { rich_linker: String, declared_linker: String },

    /// DOS stub differs from the standard MSVC stub. Free space for a mark.
    NonStandardDosStub { offset: u64, size: u64 },

    /// PDB path present. Frequently contains a username or project name.
    DebugPathPresent { path: String },

    /// Compile timestamp is zero, in the future, or absurdly old.
    ImplausibleTimestamp { value: u32 },

    /// Timestamp is a reproducible-build hash rather than a real time.
    ReproducibleBuildTimestamp { value: u32 },

    /// Version resource fields are empty, contradictory, or impersonate a
    /// known vendor.
    VersionInfoAnomaly { detail: String },

    /// Resource language IDs that conflict with the declared vendor.
    UnexpectedResourceLanguage { lang_id: u16 },

    // ---- Signing ----
    /// Certificate table present but the file's hash does not cover it, or
    /// the signature is self-signed / expired / revoked.
    SignatureAnomaly { detail: &'static str },

    /// Data appended after a valid signature (the signature still verifies
    /// under some parsers). Classic append-payload trick.
    DataAfterSignature { offset: u64, size: u64 },

    // ---- Security features ----
    /// ASLR, DEP, CFG, or SafeSEH disabled on a modern binary.
    MitigationDisabled { name: &'static str },

    /// Image declares a subsystem that contradicts its imports (GUI binary
    /// with console-only imports, native subsystem for a user-mode file).
    SubsystemMismatch { subsystem: u16 },

    // ---- Content ----
    /// TLS callbacks present. They execute before the entry point.
    TlsCallbacks { count: usize },

    /// .NET metadata present alongside native code.
    MixedManagedNative,

    /// An embedded executable found inside the file body.
    EmbeddedExecutable { offset: u64, format: Format, has_magic: bool },

    /// A string, path, mutex, or URL worth surfacing immediately.
    NotableString { offset: u64, value: String, reason: &'static str },

    /// Self-referential mark: an author handle, build tag, or greeting in a
    /// region that does not affect execution.
    PossibleAuthorMark { offset: u64, value: String },
}

impl Anomaly {
    pub fn severity(&self) -> Severity {
        use Anomaly::*;
        match self {
            WritableExecutableSection { .. }
            | EntryPointInWritableSection { .. }
            | EntryPointOutsideSections { .. }
            | DataAfterSignature { .. }
            | RichHeaderMismatch { .. }
            | DynamicResolutionOnly { .. }
            | EmbeddedExecutable { .. } => Severity::Suspicious,

            SectionSizeMismatch { .. }
            | DuplicateSectionName { .. }
            | SignatureAnomaly { .. }
            | RichHeaderAnomaly { .. }
            | ImplausibleTimestamp { .. }
            | SubsystemMismatch { .. }
            | IrregularImportLayout { .. }
            | VersionInfoAnomaly { .. } => Severity::Malformed,

            ReproducibleBuildTimestamp { .. } | Overlay { .. } | NoImports => Severity::Info,

            _ => Severity::Notable,
        }
    }
}
