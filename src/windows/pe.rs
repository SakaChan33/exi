use crate::binary::{Binary, System, Meta, Section};

const MAGIC: u16 = 0x5A4D; // MZ
const SIGNATURE: u32 = 0x00004550; // PE00
const OPTIONAL_MAGIC_PE32: u16 = 0x10B; // PE32
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20B; // PE32+


















#[derive(Clone, Debug, Default)]
pub struct Meta {
    // timestamp
    // reproducible build
    // subsystem
    // dll characteristics
    // is_dotnet
    // signed
    // resources
    // tls_callbacks
}