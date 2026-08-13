use crate::errors::{Severity, ParseError, ParseResult, Anomaly, Format};

/*
    Always treat bytes as untrusted.

    When we want to parse bytes, we don't want to blindly read the location
    of the bytes we observe. Instead, we first want to check that the region
    we are about to touch is actually inside the buffer. Secondly, we want to
    read what is there. Third, we hand back a Result instead of a value, so a
    caller cannot accidentally use a read that never happened. Those first two
    steps are the "bounds" check, and they have to happen in that order. If we
    slice first and check later, we have already panicked.

    Nothing in this file trusts a length, a count, or an offset that came out
    of the file. Every one of those is a number an author chose, and we are
    reading files whose authors did not want to be read.

    We check for bytes because of three simple reasons:

    1.) Unexpected bytes: If we are looking at a DOS header, we would expect to
    see 0x4D 0x5A (MZ) to denote that this program is a MS-DOS (Microsoft)
    executable. The operating system will automatically "bail" if this is
    corrupted or absent, so on disk, a real .exe basically always has it. Since
    we are not running the program but peeking into it, we want to see if the
    DOS header has been manipulated or corrupted in any way. A payload that is
    never handed to the Windows loader does not need the magic at all: a custom
    or reflective loader maps the sections itself and can patch the two bytes
    back in at runtime, so stripped or replaced magic with an otherwise intact
    header is a deliberate act, not damage. That is the case StrippedMagic
    exists for.

    Note the byte order. On disk the two bytes are 0x4D 0x5A in that order, but
    when we read them as a little-endian u16 the value is 0x5A4D, which is what
    the constant in pe.rs compares against. Same bytes, different read width.
    Getting this backwards is an easy way to reject every valid file we see.

    2.) What are the bytes after, but still within that DOS header? The header
    is 64 bytes, and the operating system only cares about two fields in it:
    e_magic at offset 0x00 and e_lfanew at offset 0x3C, which is the file offset
    of the PE signature. Everything in between (e_cblp, e_cp, the e_res and
    e_res2 reserved arrays, e_oemid, e_oeminfo) is ignored by the loader, as is
    the DOS stub program that sits between the header and e_lfanew. That is a
    couple hundred unvalidated bytes that ride along in every PE. The Rich
    header lives in that gap, and so does anything an author wants to carry
    without affecting execution. We parse it because nobody checks it, not
    because the format needs us to.

    3.) An offset is not one thing, and this is where a parser gets fooled.
    There are three separate address spaces in play and they do not agree with
    each other:

        - File offset: a position in the buffer we hold. This is the only one
          that is bounded by data.len(), and the only one we can slice with.
        - RVA: an offset from ImageBase after the loader has mapped the image.
        - VA: ImageBase + RVA, an actual runtime address.

    Header fields mix these freely. AddressOfEntryPoint is an RVA, but
    PointerToRawData is a file offset, and they sit in the same structures. An
    RVA cannot be used as an index into our buffer. It has to be translated
    through the section table first, and that translation is allowed to fail:
    an RVA can land in a gap the section table does not cover, or in a section
    whose virtual size exceeds its raw size, which means the bytes only exist
    once the loader zero-fills them. There is nothing in the file to read.
    That is what RvaNotMapped and RvaInUninitializedData are for.

    The reason the two layouts differ at all is alignment. FileAlignment
    (usually 512) governs where sections sit on disk. SectionAlignment (usually
    4096, matching the page size, since the kernel maps memory a page at a
    time) governs where they sit in memory. So the same section is at one
    offset in the file and a different one in the image, and the distance
    between them grows with every section. Assuming they are the same is the
    single easiest way to read the wrong bytes and still get plausible-looking
    output.

    Also worth remembering: the code of a statically linked library is part of
    the file and sits in .text with everything else, so we cannot separate it
    out and we should not try. A dynamically linked library is not in the file
    at all. What we get for those is the import table, which is names and
    thunks, not the library's code. So "am I reading the program or a library"
    is not the question a bounds check answers.

    What a failed bounds check protects us from is not reading zeros. Reading
    past the end of a slice in Rust panics, and a panic on a hostile file means
    the file killed the tool that was inspecting it. A crafted size field that
    we hand straight to an allocation does the same thing more slowly. Both are
    the file attacking the parser, which is why the limit cases in errors.rs are
    rated as suspicious and not just fatal.

    We do these bound and generalized checks to ensure we are in a region that
    actually contains bytes, that we know which address space the offset we were
    given belongs to, and that we aren't interpreting bad data as if it were
    real structure.
*/

pub struct Bytes<'a> {
    data: &'a [u8],
}

impl<'a> Bytes<'a> {

}