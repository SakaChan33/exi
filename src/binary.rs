// End of file tests are purposely omitted at the moment

use std::fmt;

#[derive(Debug, Clone)]
pub enum System {
    Windows,
    Linux,
    Mac,
    Coff, // No DOS stub or optional header
}

#[derive(Clone, Debug)]
pub struct ImportFn {

}


#[derive(Debug, Clone)]
pub enum Architecture { // Probably not needed
    x86,
    x64,
    Arch32,
    AArch64,
    PowerPC,
    PowerPC64,
    MIPS,
}

impl Architecture {

}

impl ImportFn {

}

#[derive(Debug, Clone)]
pub struct Import {

}

impl Import {

}

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

#[derive(Debug, Clone)]
pub struct Export {

}

impl Export {

}

#[derive(Debug, Clone)]
pub struct Relocation {

}

impl Relocation {

}

#[derive(Debug, Clone)]
pub struct Overlay {
    pub offset: u64, // where undescribed region starts
    pub size: u64, // size of undescribed region
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub system: System,
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