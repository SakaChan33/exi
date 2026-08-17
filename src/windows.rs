// Windows executable formats.
//
// pe.rs handles the full Portable Executable image. coff.rs handles the COFF
// file header that PE is built on top of, which lives here rather than in
// shared/ because nothing outside the Windows family reads it.

pub mod coff;
pub mod pe;
