// Format-independent work.
//
// Everything in here operates on bytes or on an already-parsed Binary, and
// none of it needs to know whether those bytes came out of a PE, an ELF or a
// Mach-O. Anything that does need to know belongs under windows/, linux/ or
// mac/ instead.

pub mod cfg;
pub mod entropy;
pub mod exports;
pub mod functions;
pub mod imports;
pub mod strings;
pub mod symbols;
