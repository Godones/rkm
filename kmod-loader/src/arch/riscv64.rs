use goblin::elf::{Elf, RelocSection, SectionHeader, SectionHeaders};
use int_enum::IntEnum;

use super::*;
use crate::{
    ModuleErr, Result,
    arch::{Ptr, get_rela_sym_idx, get_rela_type},
    loader::{KernelModuleHelper, ModuleLoadInfo, ModuleOwner},
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PltEntry {
    /// Trampoline code to real target address. The return address
    /// should be the original (pc+4) before entring plt entry.
    insn_auipc: u32, /* auipc t0, 0x0      */
    insn_ld: u32, /* ld    t1, 0x10(t0) */
    insn_jr: u32, /* jr    t1           */
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, IntEnum, PartialEq, Eq)]
#[allow(non_camel_case_types)]
/// See <https://github.com/gimli-rs/object/blob/af3ca8a2817c8119e9b6d801bd678a8f1880309d/crates/examples/src/readobj/elf.rs#L3124>
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/uapi/asm/elf.h#L40>
pub enum ArchRelocationType {
    /// None
    R_RISCV_NONE = 0,
    /// Runtime relocation: word32 = S + A
    R_RISCV_32 = 1,
    /// Runtime relocation: word64 = S + A
    R_RISCV_64 = 2,
    /// Runtime relocation: word32,64 = B + A
    R_RISCV_RELATIVE = 3,
    /// Runtime relocation: must be in executable, not allowed in shared library
    R_RISCV_COPY = 4,
    /// Runtime relocation: word32,64 = S; handled by PLT unless LD_BIND_NOW
    R_RISCV_JUMP_SLOT = 5,
    /// TLS relocation: word32 = S->TLSINDEX
    R_RISCV_TLS_DTPMOD32 = 6,
    /// TLS relocation: word64 = S->TLSINDEX
    R_RISCV_TLS_DTPMOD64 = 7,
    /// TLS relocation: word32 = TLS + S + A - TLS_TP_OFFSET
    R_RISCV_TLS_DTPREL32 = 8,
    /// TLS relocation: word64 = TLS + S + A - TLS_TP_OFFSET
    R_RISCV_TLS_DTPREL64 = 9,
    /// TLS relocation: word32 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
    R_RISCV_TLS_TPREL32 = 10,
    /// TLS relocation: word64 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
    R_RISCV_TLS_TPREL64 = 11,
    /// PC-relative branch (SB-Type)
    R_RISCV_BRANCH = 16,
    /// PC-relative jump (UJ-Type)
    R_RISCV_JAL = 17,
    /// PC-relative call: MACRO call,tail (auipc+jalr pair)
    R_RISCV_CALL = 18,
    /// PC-relative call (PLT): MACRO call,tail (auipc+jalr pair) PIC
    R_RISCV_CALL_PLT = 19,
    /// PC-relative GOT reference: MACRO la
    R_RISCV_GOT_HI20 = 20,
    /// PC-relative TLS IE GOT offset: MACRO la.tls.ie
    R_RISCV_TLS_GOT_HI20 = 21,
    /// PC-relative TLS GD reference: MACRO la.tls.gd
    R_RISCV_TLS_GD_HI20 = 22,
    /// PC-relative reference: %pcrel_hi(symbol) (U-Type)
    R_RISCV_PCREL_HI20 = 23,
    /// PC-relative reference: %pcrel_lo(symbol) (I-Type)
    R_RISCV_PCREL_LO12_I = 24,
    /// PC-relative reference: %pcrel_lo(symbol) (S-Type)
    R_RISCV_PCREL_LO12_S = 25,
    /// Absolute address: %hi(symbol) (U-Type)
    R_RISCV_HI20 = 26,
    /// Absolute address: %lo(symbol) (I-Type)
    R_RISCV_LO12_I = 27,
    /// Absolute address: %lo(symbol) (S-Type)
    R_RISCV_LO12_S = 28,
    /// TLS LE thread offset: %tprel_hi(symbol) (U-Type)
    R_RISCV_TPREL_HI20 = 29,
    /// TLS LE thread offset: %tprel_lo(symbol) (I-Type)
    R_RISCV_TPREL_LO12_I = 30,
    /// TLS LE thread offset: %tprel_lo(symbol) (S-Type)
    R_RISCV_TPREL_LO12_S = 31,
    /// TLS LE thread usage: %tprel_add(symbol)
    R_RISCV_TPREL_ADD = 32,
    /// 8-bit label addition: word8 = S + A
    R_RISCV_ADD8 = 33,
    /// 16-bit label addition: word16 = S + A
    R_RISCV_ADD16 = 34,
    /// 32-bit label addition: word32 = S + A
    R_RISCV_ADD32 = 35,
    /// 64-bit label addition: word64 = S + A
    R_RISCV_ADD64 = 36,
    /// 8-bit label subtraction: word8 = S - A
    R_RISCV_SUB8 = 37,
    /// 16-bit label subtraction: word16 = S - A
    R_RISCV_SUB16 = 38,
    /// 32-bit label subtraction: word32 = S - A
    R_RISCV_SUB32 = 39,
    /// 64-bit label subtraction: word64 = S - A
    R_RISCV_SUB64 = 40,
    /// GNU C++ vtable hierarchy
    R_RISCV_GNU_VTINHERIT = 41,
    /// GNU C++ vtable member usage
    R_RISCV_GNU_VTENTRY = 42,
    /// Alignment statement
    R_RISCV_ALIGN = 43,
    /// PC-relative branch offset (CB-Type)
    R_RISCV_RVC_BRANCH = 44,
    /// PC-relative jump offset (CJ-Type)
    R_RISCV_RVC_JUMP = 45,
    /// Absolute address (CI-Type)
    R_RISCV_RVC_LUI = 46,
    /// GP-relative reference (I-Type)
    R_RISCV_GPREL_I = 47,
    /// GP-relative reference (S-Type)
    R_RISCV_GPREL_S = 48,
    /// TP-relative TLS LE load (I-Type)
    R_RISCV_TPREL_I = 49,
    /// TP-relative TLS LE store (S-Type)
    R_RISCV_TPREL_S = 50,
    /// Instruction pair can be relaxed
    R_RISCV_RELAX = 51,
    /// Local label subtraction
    R_RISCV_SUB6 = 52,
    /// Local label subtraction
    R_RISCV_SET6 = 53,
    /// Local label subtraction
    R_RISCV_SET8 = 54,
    /// Local label subtraction
    R_RISCV_SET16 = 55,
    /// Local label subtraction
    R_RISCV_SET32 = 56,
    /// 32-bit PC-relative relocation: word32 = S + A - P
    R_RISCV_32_PCREL = 57,
    /// 32-bit PLT-relative relocation
    R_RISCV_PLT32 = 59,
    /// ULEB128 relocation pair start
    R_RISCV_SET_ULEB128 = 60,
    /// ULEB128 relocation pair subtraction
    R_RISCV_SUB_ULEB128 = 61,
}

/// The auipc+jalr instruction pair can reach any PC-relative offset
/// in the range [-2^31 - 2^11, 2^31 - 2^11)
const fn riscv_insn_valid_32bit_offset(offset: i64) -> bool {
    // return (-(1L << 31) - (1L << 11)) <= val && val < ((1L << 31) - (1L << 11));
    let low = (-(1i64 << 31)) - (1i64 << 11);
    let high = (1i64 << 31) - (1i64 << 11);
    low <= offset && offset < high
}

impl Rv64RelTy {
    fn apply_r_riscv_32_rela(location: Ptr, address: u64) -> Result<()> {
        if address != address as u32 as u64 {
            log::error!(
                "R_RISCV_32: target {:016x} does not fit in 32 bits",
                address
            );
            return Err(ModuleErr::ENOEXEC);
        }
        // Write the lower 32 bits to the location
        location.write(address as u32);
        Ok(())
    }

    fn apply_r_riscv_64_rela(location: Ptr, address: u64) -> Result<()> {
        // Write the full 64 bits to the location
        location.write(address);
        Ok(())
    }

    fn apply_r_riscv_branch_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;

        let imm12 = ((offset & 0x1000) << (31 - 12)) as u32;
        let imm11 = ((offset & 0x800) >> (11 - 7)) as u32;
        let imm10_5 = ((offset & 0x7e0) << (30 - 10)) as u32;
        let imm4_1 = ((offset & 0x1e) << (11 - 4)) as u32;

        let original_inst = location.read::<u32>();
        location.write((original_inst & 0x1fff07f) | imm12 | imm11 | imm10_5 | imm4_1);
        Ok(())
    }

    fn apply_r_riscv_jal_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;

        let imm20 = ((offset & 0x100000) << (31 - 20)) as u32;
        let imm19_12 = (offset & 0xff000) as u32;
        let imm11 = ((offset & 0x800) << (20 - 11)) as u32;
        let imm10_1 = ((offset & 0x7fe) << (30 - 10)) as u32;

        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xFFF) | imm20 | imm19_12 | imm11 | imm10_1);
        Ok(())
    }

    fn apply_r_riscv_rvc_branch_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        let imm8 = ((offset & 0x100) << (12 - 8)) as u16;
        let imm7_6 = ((offset & 0xc0) >> (6 - 5)) as u16;
        let imm5 = ((offset & 0x20) >> (5 - 2)) as u16;
        let imm4_3 = ((offset & 0x18) << (12 - 5)) as u16;
        let imm2_1 = ((offset & 0x6) << (12 - 10)) as u16;

        let original_inst = location.read::<u16>();
        location.write((original_inst & 0xe383) | imm8 | imm7_6 | imm5 | imm4_3 | imm2_1);
        Ok(())
    }

    fn apply_r_riscv_rvc_jump_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        let imm11 = ((offset & 0x800) << (12 - 11)) as u16;
        let imm10 = ((offset & 0x400) >> (10 - 8)) as u16;
        let imm9_8 = ((offset & 0x300) << (12 - 11)) as u16;
        let imm7 = ((offset & 0x80) >> (7 - 6)) as u16;
        let imm6 = ((offset & 0x40) << (12 - 11)) as u16;
        let imm5 = ((offset & 0x20) >> (5 - 2)) as u16;
        let imm4 = ((offset & 0x10) << (12 - 5)) as u16;
        let imm3_1 = ((offset & 0xe) << (12 - 10)) as u16;

        let original_inst = location.read::<u16>();
        location.write(
            (original_inst & 0xe003) | imm11 | imm10 | imm9_8 | imm7 | imm6 | imm5 | imm4 | imm3_1,
        );
        Ok(())
    }

    fn apply_r_riscv_pcrel_hi20_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        if !riscv_insn_valid_32bit_offset(offset) {
            log::error!(
                "R_RISCV_PCREL_HI20: target {:016x} can not be addressed by the 32-bit offset from PC = {:p}",
                address,
                location.as_ptr::<u32>()
            );
            return Err(ModuleErr::ENOEXEC);
        }
        let hi20 = (offset + 0x800) & 0xfffff000;
        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xfff) | (hi20 as u32));
        Ok(())
    }

    fn apply_r_riscv_pcrel_lo12_i_rela(location: Ptr, address: u64) -> Result<()> {
        // address is the lo12 value to fill. It is calculated before calling this handler.

        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xfffff) | ((address as u32 & 0xfff) << 20));
        Ok(())
    }

    fn apply_r_riscv_pcrel_lo12_s_rela(location: Ptr, address: u64) -> Result<()> {
        // address is the lo12 value to fill. It is calculated before calling this handler.

        let imm11_5 = (address as u32 & 0xfe0) << (31 - 11);
        let imm4_0 = (address as u32 & 0x1f) << (11 - 4);

        let original_inst = location.read::<u32>();
        location.write((original_inst & 0x1fff07f) | imm11_5 | imm4_0);
        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module.c#L149>
    fn apply_r_riscv_hi20_rela(location: Ptr, address: u64) -> Result<()> {
        // Compute HI20 using 32-bit signed arithmetic, matching C implementation
        let address32 = address as i32;
        // Mirror C: ((s32)v + 0x800) & 0xfffff000
        // Do the wrapping add in i32, then mask in u32 to avoid overflowing literal issues.
        let hi20 = ((address32.wrapping_add(0x800)) as u32) & 0xfffff000u32;
        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xfff) | hi20);
        Ok(())
    }

    fn apply_r_riscv_lo12_i_rela(location: Ptr, address: u64) -> Result<()> {
        // Skip medlow checking because of filtering by HI20 already

        let address = address as i32;
        let hi20 = (address.wrapping_add(0x800)) & (0xfffff000_u32 as i32);
        let lo12 = address.wrapping_sub(hi20);
        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xfffff) | ((lo12 as u32 & 0xfff) << 20));
        Ok(())
    }

    fn apply_r_riscv_lo12_s_rela(location: Ptr, address: u64) -> Result<()> {
        // Skip medlow checking because of filtering by HI20 already

        let address = address as i32;
        let hi20 = (address.wrapping_add(0x800)) & (0xfffff000_u32 as i32);
        let lo12 = address.wrapping_sub(hi20);
        let imm11_5 = (lo12 as u32 & 0xfe0) << (31 - 11);
        let imm4_0 = (lo12 as u32 & 0x1f) << (11 - 4);
        let original_inst = location.read::<u32>();
        location.write((original_inst & 0x1fff07f) | imm11_5 | imm4_0);
        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module.c#L188>
    fn apply_r_riscv_got_hi20_rela(
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        address: u64,
    ) -> Result<()> {
        #[allow(unused_assignments)]
        let mut offset = address.wrapping_sub(location.0);
        if cfg!(feature = "module-sections") {
            // Always emit the got entry
            let got =
                module_emit_got_entry(module, sechdrs, address).expect("Failed to emit GOT entry");
            offset = got as *const GotEntry as u64;
            offset = offset.wrapping_sub(location.0);
        } else {
            log::error!(
                "{}: can not generate the GOT entry for symbol = {:#x} from PC = {:p}",
                module.name(),
                address,
                location.as_ptr::<u32>()
            );
            return Err(ModuleErr::EINVAL);
        }

        let hi20 = offset.wrapping_add(0x800) & 0xfffff000;
        let original_inst = location.read::<u32>();
        location.write((original_inst & 0xfff) | (hi20 as u32));
        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module.c#L210>
    fn apply_r_riscv_call_plt_rela(
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        address: u64,
    ) -> Result<()> {
        #[allow(unused_assignments)]
        let mut offset = address.wrapping_sub(location.0);
        if !riscv_insn_valid_32bit_offset(offset as i64) {
            // Only emit the plt entry if offset over 32-bit range
            if cfg!(feature = "module-sections") {
                let plt = module_emit_plt_entry(module, sechdrs, address)
                    .expect("Failed to emit PLT entry");
                offset = plt as *const PltEntry as u64;
                offset = offset.wrapping_sub(location.0);
            } else {
                log::error!(
                    "R_RISCV_CALL_PLT: target {:016x} can not be addressed by the 32-bit offset from PC = {:p}",
                    address,
                    location.as_ptr::<u32>()
                );
                return Err(ModuleErr::EINVAL);
            }
        }
        let hi20 = (offset.wrapping_add(0x800)) & 0xfffff000;
        let lo12 = (offset.wrapping_sub(hi20)) & 0xfff;
        let original_auipc = location.read::<u32>();
        location.write((original_auipc & 0xfff) | (hi20 as u32));
        let original_jalr_ptr = location.add(4);
        let original_jalr = original_jalr_ptr.read::<u32>();
        original_jalr_ptr.write((original_jalr & 0xfffff) | ((lo12 as u32) << 20));
        Ok(())
    }

    fn apply_r_riscv_call_rela(location: Ptr, address: u64) -> Result<()> {
        let offset = address.wrapping_sub(location.0);
        if !riscv_insn_valid_32bit_offset(offset as i64) {
            log::error!(
                "R_RISCV_CALL: target {:016x} can not be addressed by the 32-bit offset from PC = {:p}",
                address,
                location.as_ptr::<u32>()
            );
            return Err(ModuleErr::EINVAL);
        }
        let hi20 = (offset.wrapping_add(0x800)) & 0xfffff000;
        let lo12 = (offset.wrapping_sub(hi20)) & 0xfff;
        let original_auipc = location.read::<u32>();
        location.write((original_auipc & 0xfff) | (hi20 as u32));
        let original_jalr_ptr = location.add(4);
        let original_jalr = original_jalr_ptr.read::<u32>();
        original_jalr_ptr.write((original_jalr & 0xfffff) | ((lo12 as u32) << 20));
        Ok(())
    }

    fn apply_r_riscv_relax_rela(_location: Ptr, _address: u64) -> Result<()> {
        Ok(())
    }

    fn apply_r_riscv_align_rela(location: Ptr, _address: u64) -> Result<()> {
        log::error!(
            "The unexpected relocation type 'R_RISCV_ALIGN' from PC = {:p}",
            location.as_ptr::<u32>()
        );
        Err(ModuleErr::ENOEXEC)
    }

    fn apply_r_riscv_add16_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u16>();
        location.write(value.wrapping_add(address as u16));
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#328>
    fn apply_r_riscv_add8_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u8>();
        location.write(value.wrapping_add(address as u8));
        Ok(())
    }

    fn apply_r_riscv_add32_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u32>();
        location.write(value.wrapping_add(address as u32));
        Ok(())
    }

    fn apply_r_riscv_add64_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u64>();
        location.write(value.wrapping_add(address));
        Ok(())
    }

    fn apply_r_riscv_sub16_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u16>();
        location.write(value.wrapping_sub(address as u16));
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#349>
    fn apply_r_riscv_sub8_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u8>();
        location.write(value.wrapping_sub(address as u8));
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#370>
    fn apply_r_riscv_sub6_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u8>();
        location.write((value.wrapping_sub(address as u8 & 0x3f)) & 0x3f);
        Ok(())
    }

    fn apply_r_riscv_sub32_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u32>();
        location.write(value.wrapping_sub(address as u32));
        Ok(())
    }

    fn apply_r_riscv_sub64_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u64>();
        location.write(value.wrapping_sub(address));
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#379>
    fn apply_r_riscv_set6_rela(location: Ptr, address: u64) -> Result<()> {
        let value = location.read::<u8>();
        location.write((value & 0xc0) | (address as u8 & 0x3f));
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#388>
    fn apply_r_riscv_set8_rela(location: Ptr, address: u64) -> Result<()> {
        location.write(address as u8);
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#394>
    fn apply_r_riscv_set16_rela(location: Ptr, address: u64) -> Result<()> {
        location.write(address as u16);
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#401>
    fn apply_r_riscv_set32_rela(location: Ptr, address: u64) -> Result<()> {
        location.write(address as u32);
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#408>
    fn apply_r_riscv_32_pcrel_rela(location: Ptr, address: u64) -> Result<()> {
        location.write(address.wrapping_sub(location.0) as u32);
        Ok(())
    }

    /// See <https://codebrowser.dev/linux/linux/arch/riscv/kernel/module.c.html#415>
    fn apply_r_riscv_plt32_rela(
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        address: u64,
    ) -> Result<()> {
        let mut offset = address.wrapping_sub(location.0);
        if !riscv_insn_valid_32bit_offset(offset as i64) {
            if cfg!(feature = "module-sections") {
                let plt = module_emit_plt_entry(module, sechdrs, address)
                    .expect("Failed to emit PLT entry");
                offset = (plt as *const PltEntry as u64).wrapping_sub(location.0);
            } else {
                log::error!(
                    "R_RISCV_PLT32: target {:016x} can not be addressed by the 32-bit offset from PC = {:p}",
                    address,
                    location.as_ptr::<u32>()
                );
                return Err(ModuleErr::EINVAL);
            }
        }
        location.write(offset as u32);
        Ok(())
    }

    pub fn apply_relocation(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: u64,
        address: u64,
    ) -> Result<()> {
        let location = Ptr(location);
        match self {
            Rv64RelTy::R_RISCV_32 => Self::apply_r_riscv_32_rela(location, address),
            Rv64RelTy::R_RISCV_64 => Self::apply_r_riscv_64_rela(location, address),
            Rv64RelTy::R_RISCV_BRANCH => Self::apply_r_riscv_branch_rela(location, address),
            Rv64RelTy::R_RISCV_JAL => Self::apply_r_riscv_jal_rela(location, address),
            Rv64RelTy::R_RISCV_RVC_BRANCH => Self::apply_r_riscv_rvc_branch_rela(location, address),
            Rv64RelTy::R_RISCV_RVC_JUMP => Self::apply_r_riscv_rvc_jump_rela(location, address),
            Rv64RelTy::R_RISCV_PCREL_HI20 => Self::apply_r_riscv_pcrel_hi20_rela(location, address),
            Rv64RelTy::R_RISCV_PCREL_LO12_I => {
                Self::apply_r_riscv_pcrel_lo12_i_rela(location, address)
            }
            Rv64RelTy::R_RISCV_PCREL_LO12_S => {
                Self::apply_r_riscv_pcrel_lo12_s_rela(location, address)
            }
            Rv64RelTy::R_RISCV_HI20 => Self::apply_r_riscv_hi20_rela(location, address),
            Rv64RelTy::R_RISCV_LO12_I => Self::apply_r_riscv_lo12_i_rela(location, address),
            Rv64RelTy::R_RISCV_LO12_S => Self::apply_r_riscv_lo12_s_rela(location, address),
            Rv64RelTy::R_RISCV_GOT_HI20 => {
                Self::apply_r_riscv_got_hi20_rela(module, sechdrs, location, address)
            }
            Rv64RelTy::R_RISCV_CALL_PLT => {
                Self::apply_r_riscv_call_plt_rela(module, sechdrs, location, address)
            }
            Rv64RelTy::R_RISCV_CALL => Self::apply_r_riscv_call_rela(location, address),
            Rv64RelTy::R_RISCV_RELAX => Self::apply_r_riscv_relax_rela(location, address),
            Rv64RelTy::R_RISCV_ALIGN => Self::apply_r_riscv_align_rela(location, address),
            Rv64RelTy::R_RISCV_ADD8 => Self::apply_r_riscv_add8_rela(location, address),
            Rv64RelTy::R_RISCV_ADD16 => Self::apply_r_riscv_add16_rela(location, address),
            Rv64RelTy::R_RISCV_ADD32 => Self::apply_r_riscv_add32_rela(location, address),
            Rv64RelTy::R_RISCV_ADD64 => Self::apply_r_riscv_add64_rela(location, address),
            Rv64RelTy::R_RISCV_SUB8 => Self::apply_r_riscv_sub8_rela(location, address),
            Rv64RelTy::R_RISCV_SUB16 => Self::apply_r_riscv_sub16_rela(location, address),
            Rv64RelTy::R_RISCV_SUB32 => Self::apply_r_riscv_sub32_rela(location, address),
            Rv64RelTy::R_RISCV_SUB64 => Self::apply_r_riscv_sub64_rela(location, address),
            Rv64RelTy::R_RISCV_SUB6 => Self::apply_r_riscv_sub6_rela(location, address),
            Rv64RelTy::R_RISCV_SET6 => Self::apply_r_riscv_set6_rela(location, address),
            Rv64RelTy::R_RISCV_SET8 => Self::apply_r_riscv_set8_rela(location, address),
            Rv64RelTy::R_RISCV_SET16 => Self::apply_r_riscv_set16_rela(location, address),
            Rv64RelTy::R_RISCV_SET32 => Self::apply_r_riscv_set32_rela(location, address),
            Rv64RelTy::R_RISCV_32_PCREL => Self::apply_r_riscv_32_pcrel_rela(location, address),
            Rv64RelTy::R_RISCV_PLT32 => {
                Self::apply_r_riscv_plt32_rela(module, sechdrs, location, address)
            }
            _ => {
                log::error!("RISC-V relocation {:?} not implemented yet", self);
                Err(ModuleErr::ENOEXEC)
            }
        }
    }
}

type Rv64RelTy = ArchRelocationType;

pub struct ArchRelocate;

#[allow(unused_assignments)]
impl ArchRelocate {
    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module.c#L313>
    pub fn apply_relocate_add<H: KernelModuleHelper>(
        rela_list: &[goblin::elf64::reloc::Rela],
        rel_section: &SectionHeader,
        sechdrs: &SectionHeaders,
        load_info: &ModuleLoadInfo,
        module: &mut ModuleOwner<H>,
    ) -> Result<()> {
        for rela in rela_list {
            let rel_type = get_rela_type(rela.r_info);
            let sym_idx = get_rela_sym_idx(rela.r_info);

            // This is where to make the change
            let location = sechdrs[rel_section.sh_info as usize]
                .sh_addr
                .wrapping_add(rela.r_offset);

            let reloc_type = ArchRelocationType::try_from(rel_type).map_err(|_| {
                log::error!(
                    "[{:?}]: Invalid relocation type: {}",
                    module.name(),
                    rel_type
                );
                ModuleErr::EINVAL
            })?;

            let (sym, sym_name) = &load_info.syms[sym_idx];

            let mut target_addr = sym.st_value.wrapping_add(rela.r_addend as u64);

            if reloc_type == Rv64RelTy::R_RISCV_PCREL_LO12_I
                || reloc_type == Rv64RelTy::R_RISCV_PCREL_LO12_S
            {
                // PC-relative relocation
                let mut find = false;
                for inner_rela in rela_list {
                    let hi20_loc = sechdrs[rel_section.sh_info as usize]
                        .sh_addr
                        .wrapping_add(inner_rela.r_offset);
                    let hi20_type = get_rela_type(inner_rela.r_info);
                    let hi20_type = Rv64RelTy::try_from(hi20_type).map_err(|_| {
                        log::error!(
                            "[{:?}]: ({}) Invalid relocation type: {}",
                            module.name(),
                            sym_name,
                            hi20_type
                        );
                        ModuleErr::EINVAL
                    })?;

                    // Find the corresponding HI20 relocation entry
                    if hi20_loc == sym.st_value
                        && (hi20_type == Rv64RelTy::R_RISCV_PCREL_HI20
                            || hi20_type == Rv64RelTy::R_RISCV_GOT_HI20)
                    {
                        let (hi20_sym, _) = load_info.syms[get_rela_sym_idx(inner_rela.r_info)];

                        let hi20_sym_val =
                            hi20_sym.st_value.wrapping_add(inner_rela.r_addend as u64);
                        // Calculate lo12
                        let mut offset = hi20_sym_val.wrapping_sub(hi20_loc);

                        if cfg!(feature = "module-sections")
                            && hi20_type == Rv64RelTy::R_RISCV_GOT_HI20
                        {
                            let got = module_emit_got_entry(module, sechdrs, hi20_sym_val)
                                .expect("Failed to emit GOT entry");
                            offset = got as *const GotEntry as u64;
                            offset = offset.wrapping_sub(hi20_loc);
                        }

                        let hi_20 = (offset.wrapping_add(0x800)) & 0xfffff000;
                        let lo_12 = offset.wrapping_sub(hi_20);

                        // update target_addr
                        target_addr = lo_12;
                        find = true;
                        break;
                    }
                }
                if !find {
                    log::error!(
                        "[{:?}]: ({}) Can not find HI20 relocation information for LO12 relocation",
                        module.name(),
                        sym_name
                    );
                    return Err(ModuleErr::EINVAL);
                }
            }
            let res = reloc_type.apply_relocation(module, sechdrs, location, target_addr);
            match res {
                Err(e) => {
                    log::error!("[{:?}]: ({}) {:?}", module.name(), sym_name, e);
                    return Err(e);
                }
                Ok(_) => { /* Successfully applied relocation */ }
            }
        }
        Ok(())
    }
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module-sections.c#L90>
pub fn module_frob_arch_sections<H: KernelModuleHelper>(
    elf: &mut Elf,
    owner: &mut ModuleOwner<H>,
) -> Result<()> {
    common_module_frob_arch_sections(elf, owner, count_max_entries, ".got.plt")
}

fn count_max_entries(rela_sec: &RelocSection) -> (usize, usize) {
    let mut plt_entries = 0;
    let mut got_entries = 0;
    for (idx, rela) in rela_sec.iter().enumerate() {
        let rel_type = rela.r_type;
        let reloc_type = Rv64RelTy::try_from(rel_type).expect("Invalid relocation type");
        match reloc_type {
            Rv64RelTy::R_RISCV_CALL_PLT => {
                if !duplicate_rela(rela_sec, idx) {
                    plt_entries += 1;
                }
            }
            Rv64RelTy::R_RISCV_PLT32 => {
                if !duplicate_rela(rela_sec, idx) {
                    plt_entries += 1;
                }
            }
            Rv64RelTy::R_RISCV_GOT_HI20 => {
                if !duplicate_rela(rela_sec, idx) {
                    got_entries += 1;
                }
            }
            _ => { /* Other relocation types do not require GOT/PLT entries */ }
        }
    }
    (plt_entries, got_entries)
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module-sections.c#L13>
fn module_emit_got_entry(
    module: &mut ModuleOwner<impl KernelModuleHelper>,
    sechdrs: &SectionHeaders,
    address: u64,
) -> Option<&'static mut GotEntry> {
    common_module_emit_got_entry(&mut module.arch.got, sechdrs, address).ok()
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/kernel/module-sections.c#L32>
fn module_emit_plt_entry(
    module: &mut ModuleOwner<impl KernelModuleHelper>,
    sechdrs: &SectionHeaders,
    address: u64,
) -> Option<&'static mut PltEntry> {
    let arch = &mut module.arch;
    common_module_emit_indexed_plt_entry(
        &mut arch.plt,
        &mut arch.plt_idx,
        sechdrs,
        address,
        emit_plt_entry_func,
    )
    .ok()
}

const OPC_AUIPC: u32 = 0x0017;
const OPC_LD: u32 = 0x3003;
const OPC_JALR: u32 = 0x0067;
const REG_T0: u32 = 0x5;
const REG_T1: u32 = 0x6;

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/module.h#L64>
fn emit_plt_entry_func(_address: u64, plt_entry_addr: u64, plt_idx_entry_addr: u64) -> PltEntry {
    /*
     * U-Type encoding:
     * +------------+----------+----------+
     * | imm[31:12] | rd[11:7] | opc[6:0] |
     * +------------+----------+----------+
     *
     * I-Type encoding:
     * +------------+------------+--------+----------+----------+
     * | imm[31:20] | rs1[19:15] | funct3 | rd[11:7] | opc[6:0] |
     * +------------+------------+--------+----------+----------+
     *
     */
    // Match C unsigned arithmetic semantics even when overflow checks are enabled.
    let offset = plt_idx_entry_addr.wrapping_sub(plt_entry_addr);
    let hi20 = (offset.wrapping_add(0x800) & 0xfffff000) as u32;
    let lo12 = offset.wrapping_sub(hi20 as u64) as u32;
    PltEntry {
        insn_auipc: OPC_AUIPC | (REG_T0 << 7) | hi20,
        insn_ld: OPC_LD | (lo12 << 20) | (REG_T0 << 15) | (REG_T1 << 7),
        insn_jr: OPC_JALR | (REG_T1 << 15),
    }
}
