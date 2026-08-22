// Core model.
pub mod binary;
pub mod errors;
pub mod limits;

// Reading and dispatch.
pub mod parse;
pub mod reader;
pub mod reader_v2;

// Per-format parsers.
pub mod linux;
pub mod mac;
pub mod windows;

// Format-independent analysis.
pub mod shared;

// Output.
pub mod cli;
pub mod hex;
pub mod json;
pub mod report;


// For testing:
pub mod binary_v2;
