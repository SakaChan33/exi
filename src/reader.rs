use std::arch::x86_64;

use crate::errors::ParseError;

#[derive(Debug, Clone, Copy)]
pub struct Bytes<'a> {
    data: &'a [u8],
}

/*
    Currently, writing specifically for little-endian
    has more use since the newer architectures use it. 

    We will probably need to support big-endian since we
    do want to support MIPS architectures.

    Pointless to write 4 separate functions for both 
    little (4) and big (4) endians when we can probably just do
    it in four.
*/
impl<'a> Bytes<'a> {
    // Define a "reader" of the input slice
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    // Similar to rate limiting but for file size
    // Uses `ParseError::FileTooLarge` to stop oversized input early
    // Still don't know what size is acceptable for "oversized"
    pub fn limit() -> Result<Self, ParseError> {

    }

    // Number of bytes in file
    pub fn len(&self) -> usize {
        self.data.len()
    }

    // Are there bytes to read?
    pub fn empty(&self) -> bool {
        self.data.empty()
    }

    pub fn slice(&self) -> Result<> {
        
    }

    pub fn u8() -> Result<> {
        // little-endian first
        // big-endian second
    }

    pub fn u16() -> Result<> {
        // little-endian first
        // big-endian second
    }

    pub fn u32() -> Result<> {
        // little-endian first
        // big-endian second
    }

    pub fn u64() -> Result<> {
        // little-endian first
        // big-endian second
    }
}