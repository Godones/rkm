#[macro_use]
mod inst;
use goblin::elf::{Elf, RelocSection, SectionHeader, SectionHeaders};
use int_enum::IntEnum;

use crate::{
    ModuleErr, Result,
    arch::{loongarch64::inst::*, *},
    loader::*,
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PltEntry {
    inst_lu12iw: u32,
    inst_lu32id: u32,
    inst_lu52id: u32,
    inst_jirl: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, IntEnum, PartialEq, Eq)]
#[allow(non_camel_case_types)]
/// See <https://github.com/gimli-rs/object/blob/af3ca8a2817c8119e9b6d801bd678a8f1880309d/crates/examples/src/readobj/elf.rs#L3251>
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/include/asm/elf.h#L24>
pub enum ArchRelocationType {
    R_LARCH_NONE = 0,
    R_LARCH_32 = 1,
    R_LARCH_64 = 2,
    R_LARCH_RELATIVE = 3,
    R_LARCH_COPY = 4,
    R_LARCH_JUMP_SLOT = 5,
    R_LARCH_TLS_DTPMOD32 = 6,
    R_LARCH_TLS_DTPMOD64 = 7,
    R_LARCH_TLS_DTPREL32 = 8,
    R_LARCH_TLS_DTPREL64 = 9,
    R_LARCH_TLS_TPREL32 = 10,
    R_LARCH_TLS_TPREL64 = 11,
    R_LARCH_IRELATIVE = 12,
    R_LARCH_TLS_DESC32 = 13,
    R_LARCH_TLS_DESC64 = 14,
    R_LARCH_MARK_LA = 20,
    R_LARCH_MARK_PCREL = 21,
    R_LARCH_SOP_PUSH_PCREL = 22,
    R_LARCH_SOP_PUSH_ABSOLUTE = 23,
    R_LARCH_SOP_PUSH_DUP = 24,
    R_LARCH_SOP_PUSH_GPREL = 25,
    R_LARCH_SOP_PUSH_TLS_TPREL = 26,
    R_LARCH_SOP_PUSH_TLS_GOT = 27,
    R_LARCH_SOP_PUSH_TLS_GD = 28,
    R_LARCH_SOP_PUSH_PLT_PCREL = 29,
    R_LARCH_SOP_ASSERT = 30,
    R_LARCH_SOP_NOT = 31,
    R_LARCH_SOP_SUB = 32,
    R_LARCH_SOP_SL = 33,
    R_LARCH_SOP_SR = 34,
    R_LARCH_SOP_ADD = 35,
    R_LARCH_SOP_AND = 36,
    R_LARCH_SOP_IF_ELSE = 37,
    R_LARCH_SOP_POP_32_S_10_5 = 38,
    R_LARCH_SOP_POP_32_U_10_12 = 39,
    R_LARCH_SOP_POP_32_S_10_12 = 40,
    R_LARCH_SOP_POP_32_S_10_16 = 41,
    R_LARCH_SOP_POP_32_S_10_16_S2 = 42,
    R_LARCH_SOP_POP_32_S_5_20 = 43,
    R_LARCH_SOP_POP_32_S_0_5_10_16_S2 = 44,
    R_LARCH_SOP_POP_32_S_0_10_10_16_S2 = 45,
    R_LARCH_SOP_POP_32_U = 46,
    R_LARCH_ADD8 = 47,
    R_LARCH_ADD16 = 48,
    R_LARCH_ADD24 = 49,
    R_LARCH_ADD32 = 50,
    R_LARCH_ADD64 = 51,
    R_LARCH_SUB8 = 52,
    R_LARCH_SUB16 = 53,
    R_LARCH_SUB24 = 54,
    R_LARCH_SUB32 = 55,
    R_LARCH_SUB64 = 56,
    R_LARCH_GNU_VTINHERIT = 57,
    R_LARCH_GNU_VTENTRY = 58,
    R_LARCH_B16 = 64,
    R_LARCH_B21 = 65,
    R_LARCH_B26 = 66,
    R_LARCH_ABS_HI20 = 67,
    R_LARCH_ABS_LO12 = 68,
    R_LARCH_ABS64_LO20 = 69,
    R_LARCH_ABS64_HI12 = 70,
    R_LARCH_PCALA_HI20 = 71,
    R_LARCH_PCALA_LO12 = 72,
    R_LARCH_PCALA64_LO20 = 73,
    R_LARCH_PCALA64_HI12 = 74,
    R_LARCH_GOT_PC_HI20 = 75,
    R_LARCH_GOT_PC_LO12 = 76,
    R_LARCH_GOT64_PC_LO20 = 77,
    R_LARCH_GOT64_PC_HI12 = 78,
    R_LARCH_GOT_HI20 = 79,
    R_LARCH_GOT_LO12 = 80,
    R_LARCH_GOT64_LO20 = 81,
    R_LARCH_GOT64_HI12 = 82,
    R_LARCH_TLS_LE_HI20 = 83,
    R_LARCH_TLS_LE_LO12 = 84,
    R_LARCH_TLS_LE64_LO20 = 85,
    R_LARCH_TLS_LE64_HI12 = 86,
    R_LARCH_TLS_IE_PC_HI20 = 87,
    R_LARCH_TLS_IE_PC_LO12 = 88,
    R_LARCH_TLS_IE64_PC_LO20 = 89,
    R_LARCH_TLS_IE64_PC_HI12 = 90,
    R_LARCH_TLS_IE_HI20 = 91,
    R_LARCH_TLS_IE_LO12 = 92,
    R_LARCH_TLS_IE64_LO20 = 93,
    R_LARCH_TLS_IE64_HI12 = 94,
    R_LARCH_TLS_LD_PC_HI20 = 95,
    R_LARCH_TLS_LD_HI20 = 96,
    R_LARCH_TLS_GD_PC_HI20 = 97,
    R_LARCH_TLS_GD_HI20 = 98,
    R_LARCH_32_PCREL = 99,
    R_LARCH_RELAX = 100,
    R_LARCH_DELETE = 101,
    R_LARCH_ALIGN = 102,
    R_LARCH_PCREL20_S2 = 103,
    R_LARCH_CFA = 104,
    R_LARCH_ADD6 = 105,
    R_LARCH_SUB6 = 106,
    R_LARCH_ADD_ULEB128 = 107,
    R_LARCH_SUB_ULEB128 = 108,
    R_LARCH_64_PCREL = 109,
    R_LARCH_CALL36 = 110,
    R_LARCH_TLS_DESC_PC_HI20 = 111,
    R_LARCH_TLS_DESC_PC_LO12 = 112,
    R_LARCH_TLS_DESC64_PC_LO20 = 113,
    R_LARCH_TLS_DESC64_PC_HI12 = 114,
    R_LARCH_TLS_DESC_HI20 = 115,
    R_LARCH_TLS_DESC_LO12 = 116,
    R_LARCH_TLS_DESC64_LO20 = 117,
    R_LARCH_TLS_DESC64_HI12 = 118,
    R_LARCH_TLS_DESC_LD = 119,
    R_LARCH_TLS_DESC_CALL = 120,
    R_LARCH_TLS_LE_HI20_R = 121,
    R_LARCH_TLS_LE_ADD_R = 122,
    R_LARCH_TLS_LE_LO12_R = 123,
    R_LARCH_TLS_LD_PCREL20_S2 = 124,
    R_LARCH_TLS_GD_PCREL20_S2 = 125,
    R_LARCH_TLS_DESC_PCREL20_S2 = 126,
}
type LaRelTy = ArchRelocationType;

const RELA_STACK_DEPTH: usize = 16;

const fn signed_imm_check(value: i64, bits: u32) -> bool {
    let limit = 1i64 << (bits - 1);
    value >= -limit && value < limit
}

const fn unsigned_imm_check(value: u64, bits: u32) -> bool {
    let limit = 1u64 << bits;
    value < limit
}

fn rela_stack_push(
    rela_stack: &mut [i64; RELA_STACK_DEPTH],
    rela_stack_top: &mut usize,
    value: i64,
) -> Result<()> {
    if *rela_stack_top >= RELA_STACK_DEPTH {
        log::error!(
            "rela_stack_push: stack overflow when pushing value = {}, top = {}",
            value,
            *rela_stack_top
        );
        return Err(ModuleErr::ENOEXEC);
    }
    rela_stack[*rela_stack_top] = value;
    log::debug!(
        "rela_stack_push: pushed value = {}, new top = {}",
        value,
        *rela_stack_top + 1
    );
    *rela_stack_top += 1;
    Ok(())
}

fn rela_stack_pop(
    rela_stack: &mut [i64; RELA_STACK_DEPTH],
    rela_stack_top: &mut usize,
) -> Result<i64> {
    if *rela_stack_top == 0 {
        log::error!("Relocation stack underflow");
        return Err(ModuleErr::ENOEXEC);
    }
    *rela_stack_top -= 1;
    let value = rela_stack[*rela_stack_top];
    log::debug!(
        "rela_stack_pop: popped value = {}, new top = {}",
        value,
        *rela_stack_top
    );
    Ok(value)
}

impl ArchRelocationType {
    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L278>
    fn apply_r_larch_b26(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        mut address: u64,
    ) -> Result<()> {
        let mut offset = address as i64 - location.0 as i64;
        if offset < -(SZ_128M as i64) || offset >= SZ_128M as i64 {
            let plt_entry = module_emit_plt_entry(module, sechdrs, address);
            assert!(
                plt_entry.is_some(),
                "Failed to emit PLT entry for address {:#x}",
                address
            );
            address = plt_entry.unwrap() as *mut PltEntry as u64;
        }

        offset = address as i64 - location.0 as i64;

        if offset & 3 != 0 {
            log::error!(
                "jump offset = {:#x} unaligned! dangerous R_LARCH_B26 ({:?}) relocation",
                offset,
                self
            );

            return Err(ModuleErr::ENOEXEC);
        }

        if !signed_imm_check(offset, 28) {
            log::error!(
                "jump offset = {:#x} overflow! dangerous R_LARCH_B26 ({:?}) relocation",
                offset,
                self
            );
            return Err(ModuleErr::ENOEXEC);
        }
        let instruction = location.read::<u32>();

        offset >>= 2;

        let mut inst = reg0i26_format::from_bits(instruction);

        inst.set_immediate_l(offset as u32 & 0xFFFF);
        inst.set_immediate_h(((offset as u32) >> 16) & 0x3FF);

        location.write::<u32>(inst.into_bits());

        Ok(())
    }

    fn apply_r_larch_pcala(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        location: Ptr,
        address: u64,
        _rela_stack_top: &mut usize,
        _rela_stack: &[i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let inst = location.read::<u32>();
        // Use s32 for a sign-extension deliberately.
        // s32 offset_hi20 = (void *)((v + 0x800) & ~0xfff) -
        //   (void *)((Elf_Addr)location & ~0xfff);
        let left = (address + 0x800) & !0xfff;
        let right = location.0 & !0xfff;
        // for rust, we must transfer to i32 first to do sign-extension correctly.
        let offset_hi20 = ((left as i64) - (right as i64)) as i32 as i64;

        let anchor = ((location.0 & !0xfff) as i64) + offset_hi20;
        let offset_rem = (address as i64) - anchor;

        let new_inst_val = match *self {
            LaRelTy::R_LARCH_PCALA_LO12 => {
                let mut inst = reg2i12_format::from_bits(inst);
                inst.set_immediate(address as u32 & 0xFFF);
                inst.into_bits()
            }
            LaRelTy::R_LARCH_PCALA_HI20 => {
                let address = offset_hi20 >> 12;
                let mut inst = reg1i20_format::from_bits(inst);
                inst.set_immediate(address as u32 & 0xFFFFF);
                inst.into_bits()
            }

            LaRelTy::R_LARCH_PCALA64_LO20 => {
                let address = offset_rem >> 32;
                let mut inst = reg1i20_format::from_bits(inst);
                inst.set_immediate(address as u32 & 0xFFFFF);
                inst.into_bits()
            }

            LaRelTy::R_LARCH_PCALA64_HI12 => {
                let address = offset_rem >> 52;
                let mut inst = reg2i12_format::from_bits(inst);
                inst.set_immediate(address as u32 & 0xFFF);
                inst.into_bits()
            }
            _ => {
                log::error!("{}: Unsupport relocation type: {:?}", module.name(), self);
                return Err(ModuleErr::ENOEXEC);
            }
        };
        location.write::<u32>(new_inst_val);
        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L370>
    fn apply_r_larch_32_pcrel(&self, location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        location.write::<u32>(offset as u32);
        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L379>
    fn apply_r_larch_64_pcrel(&self, location: Ptr, address: u64) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        location.write::<u64>(offset as u64);
        Ok(())
    }

    fn apply_r_larch_got_pc(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &[i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let got = module_emit_got_entry(module, sechdrs, address);

        if got.is_none() {
            return Err(ModuleErr::EINVAL);
        }
        let got = got.unwrap();

        // Match Linux's GOT_PC dispatch to PCALA relocations:
        // https://codebrowser.dev/linux/linux/arch/loongarch/kernel/module.c.html#399
        let new_ty = match self {
            LaRelTy::R_LARCH_GOT_PC_LO12 => LaRelTy::R_LARCH_PCALA_LO12,
            LaRelTy::R_LARCH_GOT_PC_HI20 => LaRelTy::R_LARCH_PCALA_HI20,
            _ => {
                log::error!("{}: Unsupport relocation type: {:?}", module.name(), self);
                return Err(ModuleErr::EINVAL);
            }
        };
        let got_address = got as *mut GotEntry as u64;
        new_ty.apply_r_larch_pcala(module, location, got_address, rela_stack_top, rela_stack)
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L104>
    fn apply_r_larch_sop_push_plt_pcrel(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: Ptr,
        mut address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        if offset < -(SZ_128M as i64) || offset >= SZ_128M as i64 {
            let plt_entry = module_emit_plt_entry(module, sechdrs, address);

            assert!(
                plt_entry.is_some(),
                "Failed to emit PLT entry for address {:#x}",
                address
            );

            address = plt_entry.unwrap() as *mut PltEntry as u64;
        }
        self.apply_r_larch_sop_push_pcrel(location, address, rela_stack_top, rela_stack)
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L73>
    fn apply_r_larch_sop_push_pcrel(
        &self,
        location: Ptr,
        address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let offset = address as i64 - location.0 as i64;
        rela_stack_push(rela_stack, rela_stack_top, offset)
    }

    fn apply_r_larch_sop_push_absolute(
        &self,
        _location: Ptr,
        address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        rela_stack_push(rela_stack, rela_stack_top, address as i64)
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L85>
    fn apply_r_larch_sop_push_dup(
        &self,
        _location: Ptr,
        _address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let opr1 = rela_stack_pop(rela_stack, rela_stack_top)?;
        rela_stack_push(rela_stack, rela_stack_top, opr1)?;
        rela_stack_push(rela_stack, rela_stack_top, opr1)?;
        Ok(())
    }

    fn apply_r_larch_sop(
        &self,
        _location: Ptr,
        _address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let mut opr3 = 0;
        if matches!(self, LaRelTy::R_LARCH_SOP_IF_ELSE) {
            opr3 = rela_stack_pop(rela_stack, rela_stack_top)?;
        }
        let opr2 = rela_stack_pop(rela_stack, rela_stack_top)?;
        let opr1 = rela_stack_pop(rela_stack, rela_stack_top)?;

        match self {
            LaRelTy::R_LARCH_SOP_AND => {
                rela_stack_push(rela_stack, rela_stack_top, opr1 & opr2)?;
            }
            LaRelTy::R_LARCH_SOP_ADD => {
                rela_stack_push(rela_stack, rela_stack_top, opr1.wrapping_add(opr2))?
            }
            LaRelTy::R_LARCH_SOP_SUB => {
                rela_stack_push(rela_stack, rela_stack_top, opr1.wrapping_sub(opr2))?
            }
            LaRelTy::R_LARCH_SOP_SL => {
                rela_stack_push(rela_stack, rela_stack_top, opr1 << opr2)?;
            }
            LaRelTy::R_LARCH_SOP_SR => {
                rela_stack_push(rela_stack, rela_stack_top, opr1 >> opr2)?;
            }
            LaRelTy::R_LARCH_SOP_IF_ELSE => {
                let result = if opr1 != 0 { opr2 } else { opr3 };
                rela_stack_push(rela_stack, rela_stack_top, result)?;
            }
            _ => {
                log::error!("Relocation type {:?} not implemented yet", self);
                return Err(ModuleErr::ENOEXEC);
            }
        }

        Ok(())
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L165>
    fn apply_r_larch_sop_imm_field(
        &self,
        location: Ptr,
        _address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let mut opr1 = rela_stack_pop(rela_stack, rela_stack_top)?;
        let overflow = || {
            log::error!(
                "opr1 = {:#x} overflow! dangerous {:?} relocation",
                opr1,
                self
            );
            ModuleErr::ENOEXEC
        };

        let unaligned = || {
            log::error!(
                "opr1 = {:#x} unaligned! dangerous {:?} relocation",
                opr1,
                self
            );
            ModuleErr::ENOEXEC
        };

        let inst = location.read::<u32>();
        match *self {
            LaRelTy::R_LARCH_SOP_POP_32_S_10_5 => {
                if !signed_imm_check(opr1, 5) {
                    return Err(overflow());
                }
                // https://codebrowser.dev/linux/linux/arch/loongarch/kernel/module.c.html#183
                let mut inst = reg2i5_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0x1F);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }
            LaRelTy::R_LARCH_SOP_POP_32_U_10_12 => {
                if !unsigned_imm_check(opr1 as u64, 12) {
                    return Err(overflow());
                }
                // (*(uint32_t *) PC) [21 ... 10] = opr [11 ... 0]
                let mut inst = reg2i12_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0xFFF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }
            LaRelTy::R_LARCH_SOP_POP_32_S_10_12 => {
                if !signed_imm_check(opr1, 12) {
                    return Err(overflow());
                }
                let mut inst = reg2i12_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0xFFF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }
            LaRelTy::R_LARCH_SOP_POP_32_S_10_16 => {
                if !signed_imm_check(opr1, 16) {
                    return Err(overflow());
                }
                let mut inst = reg2i16_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0xFFFF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }

            LaRelTy::R_LARCH_SOP_POP_32_S_10_16_S2 => {
                if opr1 % 4 != 0 {
                    return Err(unaligned());
                }
                if !signed_imm_check(opr1, 18) {
                    return Err(overflow());
                }
                opr1 >>= 2;
                // https://codebrowser.dev/linux/linux/arch/loongarch/kernel/module.c.html#214
                let mut inst = reg2i16_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0xFFFF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }

            LaRelTy::R_LARCH_SOP_POP_32_S_5_20 => {
                if !signed_imm_check(opr1, 20) {
                    return Err(overflow());
                }
                // https://codebrowser.dev/linux/linux/arch/loongarch/kernel/module.c.html#223
                let mut inst = reg1i20_format::from_bits(inst);
                inst.set_immediate(opr1 as u32 & 0xFFFFF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }

            LaRelTy::R_LARCH_SOP_POP_32_S_0_5_10_16_S2 => {
                if opr1 % 4 != 0 {
                    return Err(unaligned());
                }
                if !signed_imm_check(opr1, 23) {
                    return Err(overflow());
                }
                opr1 >>= 2;
                // https://codebrowser.dev/linux/linux/arch/loongarch/kernel/module.c.html#229
                let mut inst = reg1i21_format::from_bits(inst);
                inst.set_immediate_l(opr1 as u32 & 0xFFFF);
                inst.set_immediate_h(((opr1 as u32) >> 16) & 0x1F);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }

            LaRelTy::R_LARCH_SOP_POP_32_S_0_10_10_16_S2 => {
                if opr1 % 4 != 0 {
                    return Err(unaligned());
                }
                if !signed_imm_check(opr1, 28) {
                    return Err(overflow());
                }
                opr1 >>= 2;
                let mut inst = reg0i26_format::from_bits(inst);
                inst.set_immediate_l(opr1 as u32 & 0xFFFF);
                inst.set_immediate_h(((opr1 as u32) >> 16) & 0x3FF);
                location.write::<u32>(inst.into_bits());
                Ok(())
            }

            LaRelTy::R_LARCH_SOP_POP_32_U => {
                if !unsigned_imm_check(opr1 as u64, 32) {
                    return Err(overflow());
                }
                location.write::<u32>(opr1 as u32);
                Ok(())
            }

            _ => {
                unimplemented!("Relocation type {:?} not implemented yet", self);
            }
        }
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L256>
    fn apply_r_larch_add_sub(&self, location: Ptr, address: u64) -> Result<()> {
        match *self {
            LaRelTy::R_LARCH_ADD32 => {
                let original = location.read::<i32>();
                let result = original.wrapping_add(address as i32);
                location.write(result);
                Ok(())
            }
            LaRelTy::R_LARCH_ADD64 => {
                let original = location.read::<i64>();
                let result = original.wrapping_add(address as i64);
                location.write(result);
                Ok(())
            }
            LaRelTy::R_LARCH_SUB32 => {
                let original = location.read::<i32>();
                let result = original.wrapping_sub(address as i32);
                location.write(result);
                Ok(())
            }
            LaRelTy::R_LARCH_SUB64 => {
                let original = location.read::<i64>();
                let result = original.wrapping_sub(address as i64);
                location.write(result);
                Ok(())
            }
            _ => {
                log::error!("Relocation type {:?} not implemented yet", self);
                Err(ModuleErr::ENOEXEC)
            }
        }
    }

    fn apply_r_larch_none(&self, _location: Ptr, _address: u64) -> Result<()> {
        Ok(())
    }

    fn apply_r_larch_32(&self, location: Ptr, address: u64) -> Result<()> {
        location.write::<u32>(address as u32);
        Ok(())
    }

    fn apply_r_larch_64(&self, location: Ptr, address: u64) -> Result<()> {
        location.write::<u64>(address);
        Ok(())
    }

    pub fn apply_relocation(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &SectionHeaders,
        location: u64,
        address: u64,
        rela_stack_top: &mut usize,
        rela_stack: &mut [i64; RELA_STACK_DEPTH],
    ) -> Result<()> {
        let location = Ptr(location);

        match *self {
            LaRelTy::R_LARCH_B26 => self.apply_r_larch_b26(module, sechdrs, location, address),
            LaRelTy::R_LARCH_GOT_PC_HI20 | LaRelTy::R_LARCH_GOT_PC_LO12 => self
                .apply_r_larch_got_pc(
                    module,
                    sechdrs,
                    location,
                    address,
                    rela_stack_top,
                    rela_stack,
                ),
            LaRelTy::R_LARCH_SOP_PUSH_PLT_PCREL => self.apply_r_larch_sop_push_plt_pcrel(
                module,
                sechdrs,
                location,
                address,
                rela_stack_top,
                rela_stack,
            ),

            LaRelTy::R_LARCH_NONE => self.apply_r_larch_none(location, address),
            LaRelTy::R_LARCH_32 => self.apply_r_larch_32(location, address),
            LaRelTy::R_LARCH_64 => self.apply_r_larch_64(location, address),
            LaRelTy::R_LARCH_MARK_LA | LaRelTy::R_LARCH_MARK_PCREL => {
                self.apply_r_larch_none(location, address)
            }

            LaRelTy::R_LARCH_SOP_PUSH_PCREL => {
                self.apply_r_larch_sop_push_pcrel(location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_SOP_PUSH_ABSOLUTE => {
                self.apply_r_larch_sop_push_absolute(location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_SOP_PUSH_DUP => {
                self.apply_r_larch_sop_push_dup(location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_SOP_SUB
            | LaRelTy::R_LARCH_SOP_SL
            | LaRelTy::R_LARCH_SOP_SR
            | LaRelTy::R_LARCH_SOP_ADD
            | LaRelTy::R_LARCH_SOP_AND
            | LaRelTy::R_LARCH_SOP_IF_ELSE => {
                self.apply_r_larch_sop(location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_SOP_POP_32_S_10_5
            | LaRelTy::R_LARCH_SOP_POP_32_U_10_12
            | LaRelTy::R_LARCH_SOP_POP_32_S_10_12
            | LaRelTy::R_LARCH_SOP_POP_32_S_10_16
            | LaRelTy::R_LARCH_SOP_POP_32_S_10_16_S2
            | LaRelTy::R_LARCH_SOP_POP_32_S_5_20
            | LaRelTy::R_LARCH_SOP_POP_32_S_0_5_10_16_S2
            | LaRelTy::R_LARCH_SOP_POP_32_S_0_10_10_16_S2
            | LaRelTy::R_LARCH_SOP_POP_32_U => {
                self.apply_r_larch_sop_imm_field(location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_ADD32
            | LaRelTy::R_LARCH_ADD64
            | LaRelTy::R_LARCH_SUB8
            | LaRelTy::R_LARCH_SUB16
            | LaRelTy::R_LARCH_SUB24
            | LaRelTy::R_LARCH_SUB32
            | LaRelTy::R_LARCH_SUB64 => self.apply_r_larch_add_sub(location, address),

            LaRelTy::R_LARCH_PCALA_HI20
            | LaRelTy::R_LARCH_PCALA_LO12
            | LaRelTy::R_LARCH_PCALA64_LO20
            | LaRelTy::R_LARCH_PCALA64_HI12 => {
                self.apply_r_larch_pcala(module, location, address, rela_stack_top, rela_stack)
            }

            LaRelTy::R_LARCH_32_PCREL => self.apply_r_larch_32_pcrel(location, address),
            LaRelTy::R_LARCH_64_PCREL => self.apply_r_larch_64_pcrel(location, address),
            _ => {
                unimplemented!("Relocation type {:?} not implemented yet", self);
            }
        }
    }
}

pub struct ArchRelocate;

impl ArchRelocate {
    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module.c#L421>
    pub fn apply_relocate_add<H: KernelModuleHelper>(
        rela_list: &[goblin::elf64::reloc::Rela],
        rel_section: &SectionHeader,
        sechdrs: &SectionHeaders,
        load_info: &ModuleLoadInfo,
        module: &mut ModuleOwner<H>,
    ) -> Result<()> {
        let mut rela_stack = [0i64; RELA_STACK_DEPTH];
        let mut rela_stack_top = 0;

        for rela in rela_list {
            let rel_type = get_rela_type(rela.r_info);
            let sym_idx = get_rela_sym_idx(rela.r_info);

            // This is where to make the change
            let location = sechdrs[rel_section.sh_info as usize].sh_addr + rela.r_offset;
            let (sym, sym_name) = &load_info.syms[sym_idx];

            // if (IS_ERR_VALUE(sym->st_value)) {
            //     /* Ignore unresolved weak symbol */
            //     if (ELF_ST_BIND(sym->st_info) == STB_WEAK)
            // 	    continue;
            //     pr_warn("%s: Unknown symbol %s\n", mod->name, strtab + sym->st_name);
            //     return -ENOENT;
            // }

            let reloc_type = ArchRelocationType::try_from(rel_type).map_err(|_| {
                log::error!(
                    "[{:?}]: Invalid relocation type: {}",
                    module.name(),
                    rel_type
                );
                ModuleErr::ENOEXEC
            })?;

            let target_addr = sym.st_value.wrapping_add(rela.r_addend as u64);
            log::trace!(
                "Applying relocation: type = {:?}, location = {:#x}, target_addr = {:#x}",
                reloc_type,
                location,
                target_addr,
            );
            let res = reloc_type.apply_relocation(
                module,
                sechdrs,
                location,
                target_addr,
                &mut rela_stack_top,
                &mut rela_stack,
            );

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

fn emit_plt_entry(address: u64, _plt_entry_addr: u64, _plt_idx_entry_addr: u64) -> PltEntry {
    let lu12iw = larch_insn_gen_lu12iw(
        loongarch_gpr::LOONGARCH_GPR_T1,
        ADDR_IMM!(address, LU12IW) as _,
    );
    let lu32id = larch_insn_gen_lu32id(
        loongarch_gpr::LOONGARCH_GPR_T1,
        ADDR_IMM!(address, LU32ID) as _,
    );
    let lu52id = larch_insn_gen_lu52id(
        loongarch_gpr::LOONGARCH_GPR_T1,
        loongarch_gpr::LOONGARCH_GPR_T1,
        ADDR_IMM!(address, LU52ID) as _,
    );
    let jirl = larch_insn_gen_jirl(
        loongarch_gpr::LOONGARCH_GPR_ZERO,
        loongarch_gpr::LOONGARCH_GPR_T1,
        ADDR_IMM!(address, ORI) as _,
    );

    PltEntry {
        inst_lu12iw: lu12iw,
        inst_lu32id: lu32id,
        inst_lu52id: lu52id,
        inst_jirl: jirl,
    }
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module-sections.c#L12>
fn module_emit_got_entry(
    module: &mut ModuleOwner<impl KernelModuleHelper>,
    sechdrs: &SectionHeaders,
    address: u64,
) -> Option<&'static mut GotEntry> {
    common_module_emit_got_entry(&mut module.arch.got, sechdrs, address).ok()
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module-sections.c#L38>
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
        emit_plt_entry,
    )
    .ok()
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/loongarch/kernel/module-sections.c#L104>
pub fn module_frob_arch_sections<H: KernelModuleHelper>(
    elf: &mut Elf,
    owner: &mut ModuleOwner<H>,
) -> Result<()> {
    common_module_frob_arch_sections(elf, owner, count_max_entries, ".plt.idx")
}

fn count_max_entries(rela_sec: &RelocSection) -> (usize, usize) {
    let mut plt_entries = 0;
    let mut got_entries = 0;
    for (idx, rela) in rela_sec.iter().enumerate() {
        let rel_type = rela.r_type;
        let reloc_type = LaRelTy::try_from(rel_type).expect("Invalid relocation type");
        match reloc_type {
            LaRelTy::R_LARCH_SOP_PUSH_PLT_PCREL | LaRelTy::R_LARCH_B26 => {
                if !duplicate_rela(rela_sec, idx) {
                    plt_entries += 1;
                }
            }
            LaRelTy::R_LARCH_GOT_PC_HI20 => {
                if !duplicate_rela(rela_sec, idx) {
                    got_entries += 1;
                }
            }
            _ => { /* Other relocation types do not require GOT/PLT entries */ }
        }
    }
    (plt_entries, got_entries)
}
