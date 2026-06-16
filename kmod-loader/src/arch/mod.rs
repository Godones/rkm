#![allow(unused)]

cfg_if::cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        mod aarch64;
        pub use aarch64::*;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64;
        pub use loongarch64::*;
    } else if #[cfg(target_arch = "riscv64")] {
        mod riscv64;
        pub use riscv64::*;
    } else if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub use x86_64::*;
    } else {
        compile_error!("Unsupported architecture");
    }
}

const SZ_128M: u64 = 0x08000000;
const SZ_512K: u64 = 0x00080000;
const SZ_128K: u64 = 0x00020000;
const SZ_2K: u64 = 0x00000800;

/**
 * sign_extend64 - sign extend a 64-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<64) to sign bit
 */
pub const fn sign_extend64(value: u64, index: u32) -> i64 {
    let shift = 63 - index;
    ((value << shift) as i64) >> shift
}

/// Extracts the relocation type from the r_info field of an Elf64_Rela
const fn get_rela_type(r_info: u64) -> u32 {
    (r_info & 0xffffffff) as u32
}

/// Extracts the symbol index from the r_info field of an Elf64_Rela
const fn get_rela_sym_idx(r_info: u64) -> usize {
    (r_info >> 32) as usize
}

#[derive(Debug, Clone, Copy)]
struct Ptr(u64);
impl Ptr {
    fn as_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// Writes a value of type T to the pointer location
    pub fn write<T>(&self, value: T) {
        unsafe {
            let ptr = self.as_ptr::<T>();
            ptr.write(value);
        }
    }

    pub fn read<T>(&self) -> T {
        unsafe {
            let ptr = self.as_ptr::<T>();
            ptr.read()
        }
    }

    pub fn add(&self, offset: usize) -> Ptr {
        Ptr(self.0 + offset as u64)
    }

    pub fn as_slice<T>(&self, len: usize) -> &[T] {
        unsafe {
            let ptr = self.as_ptr::<T>();
            core::slice::from_raw_parts(ptr, len)
        }
    }
}

#[macro_export]
macro_rules! BIT {
    ($nr:expr) => {
        (1u32 << $nr)
    };
}

#[macro_export]
macro_rules! BIT_U64 {
    ($nr:expr) => {
        (1u64 << $nr)
    };
}

pub use common::*;

mod common {
    use core::mem::size_of;

    use goblin::elf::{Elf, Reloc, RelocSection, SectionHeader};

    use crate::{ModuleErr, Result};

    #[derive(Debug, Clone, Copy, Default)]
    #[repr(C)]
    pub struct ModSection {
        pub(crate) shndx: usize,
        pub(crate) num_entries: usize,
        pub(crate) max_entries: usize,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct GotEntry {
        pub(crate) symbol_addr: u64,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct PltIdxEntry {
        pub(crate) symbol_addr: u64,
    }

    #[derive(Debug, Clone, Copy, Default)]
    #[repr(C)]
    pub struct IndexedModuleArchSpecific {
        pub(crate) got: ModSection,
        pub(crate) plt: ModSection,
        pub(crate) plt_idx: ModSection,
    }

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub type ModuleArchSpecific = IndexedModuleArchSpecific;

    pub fn duplicate_rela(rela_sec: &RelocSection, idx: usize) -> bool {
        let rela_now = rela_sec.get(idx).expect("Invalid relocation index");
        for i in 0..idx {
            let rela_prev = rela_sec.get(i).expect("Invalid relocation index");
            if is_rela_equal(&rela_now, &rela_prev) {
                return true;
            }
        }
        false
    }

    fn is_rela_equal(rela1: &Reloc, rela2: &Reloc) -> bool {
        rela1.r_addend == rela2.r_addend
            && rela1.r_type == rela2.r_type
            && rela1.r_sym == rela2.r_sym
    }

    fn find_section(elf: &Elf, section_name: &str) -> Option<usize> {
        elf.section_headers
            .iter()
            .enumerate()
            .find_map(|(idx, shdr)| {
                let sec_name = elf.shdr_strtab.get_at(shdr.sh_name).unwrap_or("<unknown>");
                (sec_name == section_name).then_some(idx)
            })
    }

    fn get_got_entry(
        address: u64,
        sechdrs: &[SectionHeader],
        sec: &ModSection,
    ) -> Option<&'static mut GotEntry> {
        let got_entries_addr = sechdrs[sec.shndx].sh_addr;
        let got_entries = unsafe {
            core::slice::from_raw_parts_mut(got_entries_addr as *mut GotEntry, sec.max_entries)
        };

        got_entries[..sec.num_entries]
            .iter_mut()
            .find(|entry| entry.symbol_addr == address)
    }

    fn emit_got_entry(address: u64) -> GotEntry {
        GotEntry {
            symbol_addr: address,
        }
    }

    pub fn common_module_emit_got_entry(
        got_sec: &mut ModSection,
        sechdrs: &[SectionHeader],
        address: u64,
    ) -> Result<&'static mut GotEntry> {
        if let Some(got) = get_got_entry(address, sechdrs, got_sec) {
            return Ok(got);
        }

        if got_sec.num_entries >= got_sec.max_entries {
            log::error!("too many GOT entries");
            return Err(ModuleErr::ENOEXEC);
        }

        let idx = got_sec.num_entries;
        let got_entries_addr = sechdrs[got_sec.shndx].sh_addr;
        let got_entries = unsafe {
            core::slice::from_raw_parts_mut(got_entries_addr as *mut GotEntry, got_sec.max_entries)
        };
        got_entries[idx] = emit_got_entry(address);
        got_sec.num_entries += 1;

        Ok(&mut got_entries[idx])
    }

    pub fn common_prepare_got_section(
        elf: &mut Elf,
        got_sec: &mut ModSection,
        num_gots: usize,
        align: u64,
        extra_entries: usize,
    ) -> Result<()> {
        if num_gots + extra_entries == 0 {
            return Ok(());
        }

        let Some(got_section_idx) = find_section(elf, ".got") else {
            log::error!("module .GOT section missing");
            return Err(ModuleErr::ENOEXEC);
        };

        let shdr = &mut elf.section_headers[got_section_idx];
        shdr.sh_type = goblin::elf::section_header::SHT_NOBITS;
        shdr.sh_flags = goblin::elf::section_header::SHF_ALLOC as u64;
        shdr.sh_addralign = align;
        shdr.sh_size = ((num_gots + extra_entries) * size_of::<GotEntry>()) as u64;

        got_sec.shndx = got_section_idx;
        got_sec.num_entries = 0;
        got_sec.max_entries = num_gots;
        Ok(())
    }

    pub type ArchEmitPlainPltEntryFunc<P> = fn(address: u64, plt_entry_addr: u64) -> Result<P>;

    pub fn common_module_emit_plain_plt_entry<P>(
        plt_sec: &mut ModSection,
        sechdrs: &[SectionHeader],
        address: u64,
        arch_emit_plt_entry_func: ArchEmitPlainPltEntryFunc<P>,
    ) -> Result<&'static mut P> {
        if plt_sec.num_entries >= plt_sec.max_entries {
            log::error!("too many PLT entries");
            return Err(ModuleErr::ENOEXEC);
        }

        let idx = plt_sec.num_entries;
        let plt_entries_addr = sechdrs[plt_sec.shndx].sh_addr;
        let plt_entries = unsafe {
            core::slice::from_raw_parts_mut(plt_entries_addr as *mut P, plt_sec.max_entries)
        };
        let plt_entry_addr = &plt_entries[idx] as *const P as u64;

        plt_entries[idx] = arch_emit_plt_entry_func(address, plt_entry_addr)?;
        plt_sec.num_entries += 1;

        Ok(&mut plt_entries[idx])
    }

    pub fn common_prepare_plt_section<P>(
        elf: &mut Elf,
        plt_sec: &mut ModSection,
        num_plts: usize,
        align: u64,
        extra_entries: usize,
    ) -> Result<()> {
        if num_plts + extra_entries == 0 {
            return Ok(());
        }

        let Some(plt_section_idx) = find_section(elf, ".plt") else {
            log::error!("module .PLT section missing");
            return Err(ModuleErr::ENOEXEC);
        };

        let shdr = &mut elf.section_headers[plt_section_idx];
        shdr.sh_type = goblin::elf::section_header::SHT_PROGBITS;
        shdr.sh_flags = (goblin::elf::section_header::SHF_ALLOC
            | goblin::elf::section_header::SHF_EXECINSTR) as u64;
        shdr.sh_addralign = align;
        shdr.sh_size = ((num_plts + extra_entries) * size_of::<P>()) as u64;

        plt_sec.shndx = plt_section_idx;
        plt_sec.num_entries = 0;
        plt_sec.max_entries = num_plts;
        Ok(())
    }

    fn get_plt_idx(address: u64, sechdrs: &[SectionHeader], sec: &ModSection) -> Option<usize> {
        let plt_idx_addr = sechdrs[sec.shndx].sh_addr;
        let plt_idx_entries = unsafe {
            core::slice::from_raw_parts_mut(plt_idx_addr as *mut PltIdxEntry, sec.max_entries)
        };
        plt_idx_entries[..sec.num_entries]
            .iter()
            .position(|entry| entry.symbol_addr == address)
    }

    fn get_indexed_plt_entry<P>(
        address: u64,
        sechdrs: &[SectionHeader],
        plt_sec: &ModSection,
        plt_idx_sec: &ModSection,
    ) -> Option<&'static mut P> {
        let plt_idx = get_plt_idx(address, sechdrs, plt_idx_sec)?;
        let plt_entries_addr = sechdrs[plt_sec.shndx].sh_addr;
        let plt_entries = unsafe {
            core::slice::from_raw_parts_mut(plt_entries_addr as *mut P, plt_sec.max_entries)
        };
        Some(&mut plt_entries[plt_idx])
    }

    fn emit_plt_idx_entry(address: u64) -> PltIdxEntry {
        PltIdxEntry {
            symbol_addr: address,
        }
    }

    pub type ArchEmitIndexedPltEntryFunc<P> =
        fn(address: u64, plt_entry_addr: u64, plt_idx_entry_addr: u64) -> P;

    pub fn common_module_emit_indexed_plt_entry<P>(
        plt_sec: &mut ModSection,
        plt_idx_sec: &mut ModSection,
        sechdrs: &[SectionHeader],
        address: u64,
        arch_emit_plt_entry_func: ArchEmitIndexedPltEntryFunc<P>,
    ) -> Result<&'static mut P> {
        if let Some(plt) = get_indexed_plt_entry(address, sechdrs, plt_sec, plt_idx_sec) {
            return Ok(plt);
        }

        if plt_sec.num_entries >= plt_sec.max_entries {
            log::error!("too many PLT entries");
            return Err(ModuleErr::ENOEXEC);
        }

        let nr = plt_sec.num_entries;
        let plt_idx_addr = sechdrs[plt_idx_sec.shndx].sh_addr;
        let plt_idx_entries = unsafe {
            core::slice::from_raw_parts_mut(
                plt_idx_addr as *mut PltIdxEntry,
                plt_idx_sec.max_entries,
            )
        };
        plt_idx_entries[nr] = emit_plt_idx_entry(address);

        let plt_entries_addr = sechdrs[plt_sec.shndx].sh_addr;
        let plt_entries = unsafe {
            core::slice::from_raw_parts_mut(plt_entries_addr as *mut P, plt_sec.max_entries)
        };
        let plt_entry_addr = &plt_entries[nr] as *const P as u64;
        let plt_idx_entry_addr = &plt_idx_entries[nr] as *const PltIdxEntry as u64;

        plt_entries[nr] = arch_emit_plt_entry_func(address, plt_entry_addr, plt_idx_entry_addr);

        plt_sec.num_entries += 1;
        plt_idx_sec.num_entries += 1;

        Ok(&mut plt_entries[nr])
    }

    pub fn common_prepare_plt_idx_section(
        elf: &mut Elf,
        plt_idx_sec: &mut ModSection,
        num_plts: usize,
        section_name: &str,
        align: u64,
        extra_entries: usize,
    ) -> Result<()> {
        if num_plts + extra_entries == 0 {
            return Ok(());
        }

        let Some(plt_idx_section_idx) = find_section(elf, section_name) else {
            log::error!("module {} section missing", section_name);
            return Err(ModuleErr::ENOEXEC);
        };

        let shdr = &mut elf.section_headers[plt_idx_section_idx];
        shdr.sh_type = goblin::elf::section_header::SHT_PROGBITS;
        shdr.sh_flags = goblin::elf::section_header::SHF_ALLOC as u64;
        shdr.sh_addralign = align;
        shdr.sh_size = ((num_plts + extra_entries) * size_of::<PltIdxEntry>()) as u64;

        plt_idx_sec.shndx = plt_idx_section_idx;
        plt_idx_sec.num_entries = 0;
        plt_idx_sec.max_entries = num_plts;
        Ok(())
    }

    pub type ArchGotPltCounterFunc = fn(rela_sec: &RelocSection) -> (usize, usize);

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub fn common_module_frob_arch_sections<H: crate::KernelModuleHelper>(
        elf: &mut Elf,
        owner: &mut crate::ModuleOwner<H>,
        got_plt_counter_func: ArchGotPltCounterFunc,
        plt_idx_name: &str,
    ) -> Result<()> {
        let mut num_plts = 0;
        let mut num_gots = 0;
        for (idx, rela_sec) in elf.shdr_relocs.iter() {
            let shdr = &elf.section_headers[*idx];
            if shdr.sh_type != goblin::elf::section_header::SHT_RELA {
                continue;
            }
            let to_section = &elf.section_headers[shdr.sh_info as usize];
            if to_section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 == 0 {
                continue;
            }
            let (plt_entries, got_entries) = got_plt_counter_func(rela_sec);
            num_plts += plt_entries;
            num_gots += got_entries;
        }

        log::info!(
            "[{:?}]: Need {} PLT entries and {} GOT entries",
            owner.name(),
            num_plts,
            num_gots
        );

        common_prepare_got_section(elf, &mut owner.arch.got, num_gots, 64, 1)?;
        common_prepare_plt_section::<crate::arch::PltEntry>(
            elf,
            &mut owner.arch.plt,
            num_plts,
            64,
            1,
        )?;
        common_prepare_plt_idx_section(
            elf,
            &mut owner.arch.plt_idx,
            num_plts,
            plt_idx_name,
            64,
            1,
        )?;

        Ok(())
    }
}
