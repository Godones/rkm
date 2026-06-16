use goblin::elf::{Elf, RelocSection, SectionHeader};
use int_enum::IntEnum;

use crate::{
    ModuleErr, Result,
    arch::*,
    loader::{KernelModuleHelper, ModuleLoadInfo, ModuleOwner},
};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ModuleArchSpecific {
    got: ModSection,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, IntEnum)]
#[allow(non_camel_case_types)]
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/x86/include/asm/elf.h#L47>
pub enum ArchRelocationType {
    /// No reloc
    R_X86_64_NONE = 0,
    /// Direct 64 bit
    R_X86_64_64 = 1,
    /// PC relative 32 bit signed
    R_X86_64_PC32 = 2,
    /// 32 bit GOT entry
    R_X86_64_GOT32 = 3,
    /// 32 bit PLT address
    R_X86_64_PLT32 = 4,
    /// Copy symbol at runtime
    R_X86_64_COPY = 5,
    /// Create GOT entry
    R_X86_64_GLOB_DAT = 6,
    /// Create PLT entry
    R_X86_64_JUMP_SLOT = 7,
    /// Adjust by program base
    R_X86_64_RELATIVE = 8,
    /// 32 bit signed pc relative offset to GOT
    R_X86_64_GOTPCREL = 9,
    /// Direct 32 bit zero extended
    R_X86_64_32 = 10,
    /// Direct 32 bit sign extended
    R_X86_64_32S = 11,
    /// Direct 16 bit zero extended
    R_X86_64_16 = 12,
    /// 16 bit sign extended pc relative
    R_X86_64_PC16 = 13,
    /// Direct 8 bit sign extended
    R_X86_64_8 = 14,
    /// 8 bit sign extended pc relative
    R_X86_64_PC8 = 15,
    /// Place relative 64-bit signed
    R_X86_64_PC64 = 24,
}

type X64RelTy = ArchRelocationType;

impl ArchRelocationType {
    fn apply_r_x86_64_gotpcrel(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &[SectionHeader],
        location: u64,
        symbol_addr: u64,
        addend: i64,
    ) -> Result<()> {
        let location = Ptr(location);
        let got = common_module_emit_got_entry(&mut module.arch.got, sechdrs, symbol_addr)?;
        let got_addr = got as *const GotEntry as u64;
        let value = (got_addr as i64)
            .wrapping_add(addend)
            .wrapping_sub(location.0 as i64);

        if value != value as i32 as i64 {
            log::error!(
                "overflow in relocation type {:?}, displacement {:#x}",
                self,
                value
            );
            return Err(ModuleErr::ENOEXEC);
        }

        if location.as_slice::<u8>(4).iter().any(|&b| b != 0) {
            log::error!(
                "x86/modules: Invalid relocation target, existing value is nonzero for type {:?}, loc: {:#x}, value: {:#x}",
                self,
                location.0,
                value
            );
            return Err(ModuleErr::ENOEXEC);
        }

        location.write::<u32>(value as u32);
        Ok(())
    }

    fn apply_relocation(&self, location: u64, mut target_addr: u64) -> Result<()> {
        let size;
        let location = Ptr(location);
        let overflow = || {
            log::error!(
                "overflow in relocation type {:?}, target address {:#x}",
                self,
                target_addr
            );
            log::error!("module likely not compiled with -mcmodel=kernel");
            ModuleErr::ENOEXEC
        };
        match self {
            X64RelTy::R_X86_64_NONE => return Ok(()),
            X64RelTy::R_X86_64_64 => {
                size = 8;
            }
            X64RelTy::R_X86_64_32 => {
                if target_addr != target_addr as u32 as u64 {
                    return Err(overflow());
                }
                size = 4;
            }
            X64RelTy::R_X86_64_32S => {
                // Check if the value fits in a signed 32-bit integer
                // C code: if ((s64)val != *(s32 *)&val) goto overflow;
                // This checks: i64_value != sign_extend(low_32_bits_as_i32)
                if (target_addr as i64) != ((target_addr as i32) as i64) {
                    return Err(overflow());
                }
                size = 4;
            }
            X64RelTy::R_X86_64_PC32 | X64RelTy::R_X86_64_PLT32 => {
                target_addr = target_addr.wrapping_sub(location.0);
                size = 4;
            }
            X64RelTy::R_X86_64_PC64 => {
                target_addr = target_addr.wrapping_sub(location.0);
                size = 8;
            }
            _ => {
                log::error!("x86/modules: Unsupported relocation type: {:?}", self);
                return Err(ModuleErr::ENOEXEC);
            }
        }
        // if (memcmp(loc, &zero, size))
        if location.as_slice::<u8>(size).iter().any(|&b| b != 0) {
            log::error!(
                "x86/modules: Invalid relocation target, existing value is nonzero for type {:?}, loc: {:#x}, value: {:#x}",
                self,
                location.0,
                target_addr
            );
            return Err(ModuleErr::ENOEXEC);
        } else {
            // Write the relocated value
            match size {
                4 => location.write::<u32>(target_addr as u32),
                8 => location.write::<u64>(target_addr),
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

pub struct ArchRelocate;

#[allow(unused_assignments)]
impl ArchRelocate {
    /// See https://elixir.bootlin.com/linux/v6.6/source/arch/x86/kernel/module.c#L252
    pub fn apply_relocate_add<H: KernelModuleHelper>(
        rela_list: &[goblin::elf64::reloc::Rela],
        rel_section: &SectionHeader,
        sechdrs: &[SectionHeader],
        load_info: &ModuleLoadInfo,
        module: &mut ModuleOwner<H>,
    ) -> Result<()> {
        for rela in rela_list {
            let rel_type = get_rela_type(rela.r_info);
            let sym_idx = get_rela_sym_idx(rela.r_info);

            // This is where to make the change
            let location = sechdrs[rel_section.sh_info as usize].sh_addr + rela.r_offset;
            let (sym, sym_name) = &load_info.syms[sym_idx];

            let reloc_type = ArchRelocationType::try_from(rel_type).map_err(|_| {
                log::error!(
                    "[{:?}]: Invalid relocation type: {}",
                    module.name(),
                    rel_type
                );
                ModuleErr::ENOEXEC
            })?;

            let target_addr = sym.st_value.wrapping_add(rela.r_addend as u64);

            log::info!(
                "[{:?}]: Applying relocation {:?} at location {:#x} with target addr {:#x}",
                module.name(),
                reloc_type,
                location,
                target_addr
            );

            let res = match reloc_type {
                X64RelTy::R_X86_64_GOTPCREL => reloc_type.apply_r_x86_64_gotpcrel(
                    module,
                    sechdrs,
                    location,
                    sym.st_value,
                    rela.r_addend,
                ),
                _ => reloc_type.apply_relocation(location, target_addr),
            };
            match res {
                Err(e) => {
                    log::error!("[{:?}]: '{}' {:?}", module.name(), sym_name, e);
                    return Err(e);
                }
                Ok(_) => { /* Successfully applied relocation */ }
            }
        }
        Ok(())
    }
}

pub fn module_frob_arch_sections<H: KernelModuleHelper>(
    elf: &mut Elf,
    owner: &mut ModuleOwner<H>,
) -> Result<()> {
    let mut num_gots = 0usize;
    for (idx, rela_sec) in elf.shdr_relocs.iter() {
        let shdr = &elf.section_headers[*idx];
        if shdr.sh_type != goblin::elf::section_header::SHT_RELA {
            continue;
        }

        let to_section = &elf.section_headers[shdr.sh_info as usize];
        if to_section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 == 0 {
            continue;
        }

        num_gots += count_gots(rela_sec);
    }

    if num_gots == 0 {
        return Ok(());
    }

    common_prepare_got_section(
        elf,
        &mut owner.arch.got,
        num_gots,
        core::mem::align_of::<GotEntry>() as u64,
        0,
    )?;

    Ok(())
}

fn count_gots(rela_sec: &RelocSection) -> usize {
    rela_sec
        .iter()
        .filter(|rela| {
            matches!(
                X64RelTy::try_from(rela.r_type),
                Ok(X64RelTy::R_X86_64_GOTPCREL)
            )
        })
        .count()
}
