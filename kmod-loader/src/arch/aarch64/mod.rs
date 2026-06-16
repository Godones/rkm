mod insn;

use goblin::elf::{Elf, RelocSection, SectionHeader};
use int_enum::IntEnum;

use crate::{
    BIT, BIT_U64, ModuleErr, Result,
    arch::{aarch64::insn::*, *},
    loader::*,
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PltEntry {
    adrp: u32,
    add: u32,
    br: u32,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ModuleArchSpecific {
    got: ModSection,
    plt: ModSection,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, IntEnum, PartialEq, Eq)]
#[allow(non_camel_case_types)]
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/elf.h#L28>
/// See <https://github.com/gimli-rs/object/blob/main/src/elf.rs#L5104>
pub enum ArchRelocationType {
    // Miscellaneous
    R_ARM_NONE = 0,
    R_AARCH64_NONE = 256,
    // Data
    R_AARCH64_ABS64 = 257,
    R_AARCH64_ABS32 = 258,
    R_AARCH64_ABS16 = 259,
    R_AARCH64_PREL64 = 260,
    R_AARCH64_PREL32 = 261,
    R_AARCH64_PREL16 = 262,
    // Instructions
    R_AARCH64_MOVW_UABS_G0 = 263,
    R_AARCH64_MOVW_UABS_G0_NC = 264,
    R_AARCH64_MOVW_UABS_G1 = 265,
    R_AARCH64_MOVW_UABS_G1_NC = 266,
    R_AARCH64_MOVW_UABS_G2 = 267,
    R_AARCH64_MOVW_UABS_G2_NC = 268,
    R_AARCH64_MOVW_UABS_G3 = 269,
    R_AARCH64_MOVW_SABS_G0 = 270,
    R_AARCH64_MOVW_SABS_G1 = 271,
    R_AARCH64_MOVW_SABS_G2 = 272,
    R_AARCH64_LD_PREL_LO19 = 273,
    R_AARCH64_ADR_PREL_LO21 = 274,
    R_AARCH64_ADR_PREL_PG_HI21 = 275,
    R_AARCH64_ADR_PREL_PG_HI21_NC = 276,
    R_AARCH64_ADD_ABS_LO12_NC = 277,
    R_AARCH64_LDST8_ABS_LO12_NC = 278,
    R_AARCH64_TSTBR14 = 279,
    R_AARCH64_CONDBR19 = 280,
    R_AARCH64_JUMP26 = 282,
    R_AARCH64_CALL26 = 283,
    R_AARCH64_LDST16_ABS_LO12_NC = 284,
    R_AARCH64_LDST32_ABS_LO12_NC = 285,
    R_AARCH64_LDST64_ABS_LO12_NC = 286,
    R_AARCH64_LDST128_ABS_LO12_NC = 299,
    R_AARCH64_MOVW_PREL_G0 = 287,
    R_AARCH64_MOVW_PREL_G0_NC = 288,
    R_AARCH64_MOVW_PREL_G1 = 289,
    R_AARCH64_MOVW_PREL_G1_NC = 290,
    R_AARCH64_MOVW_PREL_G2 = 291,
    R_AARCH64_MOVW_PREL_G2_NC = 292,
    R_AARCH64_MOVW_PREL_G3 = 293,
    // P-page-rel. GOT off. ADRP 32:12.
    R_AARCH64_ADR_GOT_PAGE = 311,
    // Dir. GOT off. LD/ST imm. 11:3.
    R_AARCH64_LD64_GOT_LO12_NC = 312,
    R_AARCH64_RELATIVE = 1027,
}

type Arm64RelTy = ArchRelocationType;

const fn do_reloc(op: Aarch64RelocOp, location: Ptr, address: u64) -> u64 {
    match op {
        Aarch64RelocOp::RELOC_OP_ABS => address,
        Aarch64RelocOp::RELOC_OP_PREL => address.wrapping_sub(location.0),
        Aarch64RelocOp::RELOC_OP_PAGE => (address & !0xfff).wrapping_sub(location.0 & !0xfff),
        Aarch64RelocOp::RELOC_OP_NONE => 0,
    }
}

const AARCH64_INSN_ADRP: u32 = 0x9000_0000;
const AARCH64_INSN_ADD_IMM_64: u32 = 0x9100_0000;
const AARCH64_INSN_BR: u32 = 0xd61f_0000;
const AARCH64_REG_IP0: u32 = 16;

const fn signed_imm_check(value: i128, bits: u32) -> bool {
    value >= -(1i128 << (bits - 1)) && value < (1i128 << (bits - 1))
}

fn emit_plt_entry(address: u64, plt_entry_addr: u64) -> Result<PltEntry> {
    let target_page = (address & !0xfff) as i64 as i128;
    let plt_page = (plt_entry_addr & !0xfff) as i64 as i128;
    let page_delta = (target_page - plt_page) >> 12;

    if !signed_imm_check(page_delta, 21) {
        log::error!(
            "AArch64 PLT target {:#x} is out of ADRP range from PLT entry {:#x}",
            address,
            plt_entry_addr
        );
        return Err(ModuleErr::ENOEXEC);
    }

    let imm = (page_delta as u32) & ((1 << 21) - 1);
    let immlo = imm & 0x3;
    let immhi = (imm >> 2) & 0x7ffff;
    let adrp = AARCH64_INSN_ADRP | (immlo << 29) | (immhi << 5) | AARCH64_REG_IP0;
    let add = AARCH64_INSN_ADD_IMM_64
        | (((address & 0xfff) as u32) << 10)
        | (AARCH64_REG_IP0 << 5)
        | AARCH64_REG_IP0;
    let br = AARCH64_INSN_BR | (AARCH64_REG_IP0 << 5);

    Ok(PltEntry { adrp, add, br })
}

/// See <https://codebrowser.dev/linux/linux/arch/arm64/kernel/module-plts.c.html#69>
fn module_emit_plt_entry(
    module: &mut ModuleOwner<impl KernelModuleHelper>,
    sechdrs: &[SectionHeader],
    address: u64,
) -> Result<&'static mut PltEntry> {
    common_module_emit_plain_plt_entry(&mut module.arch.plt, sechdrs, address, emit_plt_entry)
}

fn module_emit_got_entry(
    module: &mut ModuleOwner<impl KernelModuleHelper>,
    sechdrs: &[SectionHeader],
    address: u64,
) -> Result<&'static mut GotEntry> {
    common_module_emit_got_entry(&mut module.arch.got, sechdrs, address)
}

/// TODO: Implement the function
///
/// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/module.h#L45>
fn is_forbidden_offset_for_adrp(address: u64) -> bool {
    ((address & 0xfff) >= 0xff8) && false
}

impl ArchRelocationType {
    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/kernel/module.c#L177>
    fn reloc_data(
        &self,
        op: Aarch64RelocOp,
        location: Ptr,
        address: u64,
        len: usize,
    ) -> Result<bool> {
        let s_addr = do_reloc(op, location, address) as i64;
        /*
         * The ELF psABI for AArch64 documents the 16-bit and 32-bit place
         * relative and absolute relocations as having a range of [-2^15, 2^16)
         * or [-2^31, 2^32), respectively. However, in order to be able to
         * detect overflows reliably, we have to choose whether we interpret
         * such quantities as signed or as unsigned, and stick with it.
         * The way we organize our address space requires a signed
         * interpretation of 32-bit relative references, so let's use that
         * for all R_AARCH64_PRELxx relocations. This means our upper
         * bound for overflow detection should be Sxx_MAX rather than Uxx_MAX.
         */
        match len {
            16 => {
                location.write::<i16>(s_addr as i16);
                match op {
                    Aarch64RelocOp::RELOC_OP_ABS => Ok(s_addr < 0 || s_addr > u16::MAX as i64),
                    Aarch64RelocOp::RELOC_OP_PREL => {
                        Ok(s_addr < i16::MIN as i64 || s_addr > i16::MAX as i64)
                    }
                    _ => {
                        unreachable!("Unsupported operation for AArch64 16-bit relocation")
                    }
                }
            }
            32 => {
                location.write::<i32>(s_addr as i32);
                match op {
                    Aarch64RelocOp::RELOC_OP_ABS => Ok(s_addr < 0 || s_addr > u32::MAX as i64),
                    Aarch64RelocOp::RELOC_OP_PREL => {
                        Ok(s_addr < i32::MIN as i64 || s_addr > i32::MAX as i64)
                    }
                    _ => {
                        unreachable!("Unsupported operation for AArch64 32-bit relocation")
                    }
                }
            }
            64 => {
                location.write::<u64>(s_addr as u64);
                Ok(false)
            }
            _ => unreachable!("Unsupported length for AArch64 relocation"),
        }
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/kernel/module.c#L241>
    fn reloc_insn_movw(
        &self,
        op: Aarch64RelocOp,
        location: Ptr,
        address: u64,
        lsb: i32,
        imm_type: Aarch64InsnMovwImmType,
    ) -> Result<bool> {
        let mut insn = location.read::<u32>();
        let s_addr = do_reloc(op, location, address) as i64;

        let mut imm = (s_addr >> lsb) as u64;
        if imm_type == Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ {
            /*
             * For signed MOVW relocations, we have to manipulate the
             * instruction encoding depending on whether or not the
             * immediate is less than zero.
             */
            insn &= !(3 << 29);
            if s_addr >= 0 {
                // >=0: Set the instruction to MOVZ (opcode 10b).
                insn |= 2 << 29;
            } else {
                /*
                 * <0: Set the instruction to MOVN (opcode 00b).
                 *     Since we've masked the opcode already, we
                 *     don't need to do anything other than
                 *     inverting the new immediate field.
                 */
                imm = !imm;
            }
        }
        // Update the instruction with the new encoding.
        insn = aarch64_insn_encode_immediate(Aarch64InsnImmType::AARCH64_INSN_IMM_16, insn, imm);
        location.write::<u32>(insn);

        if imm > u16::MAX as u64 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/kernel/module.c#L282>
    fn reloc_insn_imm(
        &self,
        op: Aarch64RelocOp,
        location: Ptr,
        address: u64,
        lsb: i32,
        len: i32,
        imm_type: Aarch64InsnImmType,
    ) -> Result<bool> {
        let mut insn = location.read::<u32>();
        // Calculate the relocation value.
        let mut s_addr = do_reloc(op, location, address) as i64;
        s_addr >>= lsb;
        // Extract the value bits and shift them to bit 0.
        let imm_mask = (BIT_U64!(lsb + len) - 1) >> lsb;
        let imm = (s_addr as u64) & imm_mask;

        // Update the instruction's immediate field.
        insn = aarch64_insn_encode_immediate(imm_type, insn, imm);

        location.write::<u32>(insn);

        /*
         * Extract the upper value bits (including the sign bit) and
         * shift them to bit 0.
         */
        // sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
        s_addr = (s_addr & !((imm_mask >> 1) as i64)) >> (len - 1);

        /*
         * Overflow has occurred if the upper bits are not all equal to
         * the sign bit of the value.
         */

        if (s_addr + 1) as u64 >= 2 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn reloc_insn_adrp(&self, location: Ptr, address: u64) -> Result<bool> {
        if !is_forbidden_offset_for_adrp(location.0) {
            return self.reloc_insn_imm(
                Aarch64RelocOp::RELOC_OP_PAGE,
                location,
                address,
                12,
                21,
                Aarch64InsnImmType::AARCH64_INSN_IMM_ADR,
            );
        }
        // patch ADRP to ADR if it is in range
        let ovf = self.reloc_insn_imm(
            Aarch64RelocOp::RELOC_OP_PREL,
            location,
            address & !0xfff,
            0,
            21,
            Aarch64InsnImmType::AARCH64_INSN_IMM_ADR,
        )?;
        if !ovf {
            let mut insn = location.read::<u32>();
            insn &= !BIT!(31); // clear bit 31 to convert ADRP to ADR
            location.write::<u32>(insn);
            Ok(false)
        } else {
            //  out of range for ADR -> emit a veneer
            log::error!("ADR out of range for veneer emission");
            Err(ModuleErr::ENOEXEC)
        }
    }

    fn apply_r_aarch64_adr_got_page(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &[SectionHeader],
        location: Ptr,
        address: u64,
    ) -> Result<bool> {
        let got = module_emit_got_entry(module, sechdrs, address)?;
        let got_addr = got as *const GotEntry as u64;
        self.reloc_insn_adrp(location, got_addr)
    }

    fn apply_r_aarch64_ld64_got_lo12_nc(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &[SectionHeader],
        location: Ptr,
        address: u64,
    ) -> Result<bool> {
        let got = module_emit_got_entry(module, sechdrs, address)?;
        let got_addr = got as *const GotEntry as u64;
        self.reloc_insn_imm(
            Aarch64RelocOp::RELOC_OP_ABS,
            location,
            got_addr,
            3,
            9,
            Aarch64InsnImmType::AARCH64_INSN_IMM_12,
        )
    }

    fn apply_relocation(
        &self,
        module: &mut ModuleOwner<impl KernelModuleHelper>,
        sechdrs: &[SectionHeader],
        location: u64,
        address: u64,
    ) -> Result<()> {
        // Check for overflow by default.
        let mut check_overflow = true;
        let location = Ptr(location);
        let ovf = match self {
            Arm64RelTy::R_ARM_NONE | Arm64RelTy::R_AARCH64_NONE => false,
            // Data relocations.
            Arm64RelTy::R_AARCH64_ABS64 => {
                check_overflow = false;
                self.reloc_data(Aarch64RelocOp::RELOC_OP_ABS, location, address, 64)?
            }
            Arm64RelTy::R_AARCH64_ABS32 => {
                self.reloc_data(Aarch64RelocOp::RELOC_OP_ABS, location, address, 32)?
            }
            Arm64RelTy::R_AARCH64_ABS16 => {
                self.reloc_data(Aarch64RelocOp::RELOC_OP_ABS, location, address, 16)?
            }
            Arm64RelTy::R_AARCH64_PREL64 => {
                check_overflow = false;

                self.reloc_data(Aarch64RelocOp::RELOC_OP_PREL, location, address, 64)?
            }
            Arm64RelTy::R_AARCH64_PREL32 => {
                self.reloc_data(Aarch64RelocOp::RELOC_OP_PREL, location, address, 32)?
            }
            Arm64RelTy::R_AARCH64_PREL16 => {
                self.reloc_data(Aarch64RelocOp::RELOC_OP_PREL, location, address, 16)?
            }
            // MOVW instruction relocations
            Arm64RelTy::R_AARCH64_MOVW_UABS_G0_NC | Arm64RelTy::R_AARCH64_MOVW_UABS_G0 => {
                if *self == Arm64RelTy::R_AARCH64_MOVW_UABS_G0_NC {
                    check_overflow = false;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    0,
                    Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_UABS_G1_NC | Arm64RelTy::R_AARCH64_MOVW_UABS_G1 => {
                if *self == Arm64RelTy::R_AARCH64_MOVW_UABS_G1_NC {
                    check_overflow = false;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    16,
                    Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_UABS_G2_NC | Arm64RelTy::R_AARCH64_MOVW_UABS_G2 => {
                if *self == Arm64RelTy::R_AARCH64_MOVW_UABS_G2_NC {
                    check_overflow = false;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    32,
                    Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_UABS_G3 => {
                // We're using the top bits so we can't overflow.
                check_overflow = false;
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    48,
                    Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_SABS_G0 => self.reloc_insn_movw(
                Aarch64RelocOp::RELOC_OP_ABS,
                location,
                address,
                0,
                Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ,
            )?,
            Arm64RelTy::R_AARCH64_MOVW_SABS_G1 => self.reloc_insn_movw(
                Aarch64RelocOp::RELOC_OP_ABS,
                location,
                address,
                16,
                Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ,
            )?,
            Arm64RelTy::R_AARCH64_MOVW_SABS_G2 => self.reloc_insn_movw(
                Aarch64RelocOp::RELOC_OP_ABS,
                location,
                address,
                32,
                Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ,
            )?,
            Arm64RelTy::R_AARCH64_MOVW_PREL_G0_NC | Arm64RelTy::R_AARCH64_MOVW_PREL_G0 => {
                let mut imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ;
                if *self == Arm64RelTy::R_AARCH64_MOVW_PREL_G0_NC {
                    check_overflow = false;
                    imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_PREL,
                    location,
                    address,
                    0,
                    imm_type,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_PREL_G1_NC | Arm64RelTy::R_AARCH64_MOVW_PREL_G1 => {
                let mut imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ;
                if *self == Arm64RelTy::R_AARCH64_MOVW_PREL_G1_NC {
                    check_overflow = false;
                    imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_PREL,
                    location,
                    address,
                    16,
                    imm_type,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_PREL_G2_NC | Arm64RelTy::R_AARCH64_MOVW_PREL_G2 => {
                let mut imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ;
                if *self == Arm64RelTy::R_AARCH64_MOVW_PREL_G2_NC {
                    check_overflow = false;
                    imm_type = Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVKZ;
                }
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_PREL,
                    location,
                    address,
                    32,
                    imm_type,
                )?
            }
            Arm64RelTy::R_AARCH64_MOVW_PREL_G3 => {
                // We're using the top bits so we can't overflow.
                check_overflow = false;
                self.reloc_insn_movw(
                    Aarch64RelocOp::RELOC_OP_PREL,
                    location,
                    address,
                    48,
                    Aarch64InsnMovwImmType::AARCH64_INSN_IMM_MOVNZ,
                )?
            }
            // Immediate instruction relocations.
            Arm64RelTy::R_AARCH64_LD_PREL_LO19 => self.reloc_insn_imm(
                Aarch64RelocOp::RELOC_OP_PREL,
                location,
                address,
                2,
                19,
                Aarch64InsnImmType::AARCH64_INSN_IMM_19,
            )?,
            Arm64RelTy::R_AARCH64_ADR_PREL_LO21 => self.reloc_insn_imm(
                Aarch64RelocOp::RELOC_OP_PREL,
                location,
                address,
                0,
                21,
                Aarch64InsnImmType::AARCH64_INSN_IMM_ADR,
            )?,
            Arm64RelTy::R_AARCH64_ADR_PREL_PG_HI21_NC | Arm64RelTy::R_AARCH64_ADR_PREL_PG_HI21 => {
                if *self == Arm64RelTy::R_AARCH64_ADR_PREL_PG_HI21_NC {
                    check_overflow = false;
                }
                // https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/kernel/module.c#L491
                self.reloc_insn_adrp(location, address)?
            }
            Arm64RelTy::R_AARCH64_ADD_ABS_LO12_NC | Arm64RelTy::R_AARCH64_LDST8_ABS_LO12_NC => {
                check_overflow = false;
                self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    0,
                    12,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_12,
                )?
            }
            Arm64RelTy::R_AARCH64_LDST16_ABS_LO12_NC => {
                check_overflow = false;
                self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    1,
                    11,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_12,
                )?
            }
            Arm64RelTy::R_AARCH64_LDST32_ABS_LO12_NC => {
                check_overflow = false;
                self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    2,
                    10,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_12,
                )?
            }
            Arm64RelTy::R_AARCH64_LDST64_ABS_LO12_NC => {
                check_overflow = false;
                self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    3,
                    9,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_12,
                )?
            }
            Arm64RelTy::R_AARCH64_LDST128_ABS_LO12_NC => {
                check_overflow = false;
                self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_ABS,
                    location,
                    address,
                    4,
                    8,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_12,
                )?
            }
            Arm64RelTy::R_AARCH64_TSTBR14 => self.reloc_insn_imm(
                Aarch64RelocOp::RELOC_OP_PREL,
                location,
                address,
                2,
                14,
                Aarch64InsnImmType::AARCH64_INSN_IMM_14,
            )?,
            Arm64RelTy::R_AARCH64_CONDBR19 => self.reloc_insn_imm(
                Aarch64RelocOp::RELOC_OP_PREL,
                location,
                address,
                2,
                19,
                Aarch64InsnImmType::AARCH64_INSN_IMM_19,
            )?,
            Arm64RelTy::R_AARCH64_JUMP26 | Arm64RelTy::R_AARCH64_CALL26 => {
                let mut ovf = self.reloc_insn_imm(
                    Aarch64RelocOp::RELOC_OP_PREL,
                    location,
                    address,
                    2,
                    26,
                    Aarch64InsnImmType::AARCH64_INSN_IMM_26,
                )?;
                if ovf {
                    // Linux emits a PLT entry and retries this relocation here.
                    // https://codebrowser.dev/linux/linux/arch/arm64/kernel/module.c.html#415
                    let plt = module_emit_plt_entry(module, sechdrs, address)?;
                    let plt_addr = plt as *const PltEntry as u64;
                    ovf = self.reloc_insn_imm(
                        Aarch64RelocOp::RELOC_OP_PREL,
                        location,
                        plt_addr,
                        2,
                        26,
                        Aarch64InsnImmType::AARCH64_INSN_IMM_26,
                    )?;
                }
                ovf
            }
            Arm64RelTy::R_AARCH64_ADR_GOT_PAGE => {
                // GOT-generating relocation. The GOT entry is keyed by S + A,
                // and ADRP receives Page(GOT(S + A)) - Page(P).
                // See <https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#relocations>
                self.apply_r_aarch64_adr_got_page(module, sechdrs, location, address)?
            }
            Arm64RelTy::R_AARCH64_LD64_GOT_LO12_NC => {
                // Companion relocation for ADR_GOT_PAGE. The LDR unsigned
                // immediate is scaled by 8, so encode GOT(S + A)[11:3].
                // See <https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#relocations>
                check_overflow = false;
                self.apply_r_aarch64_ld64_got_lo12_nc(module, sechdrs, location, address)?
            }
            _ => {
                log::error!("Relocation type {:?} not implemented yet", self);
                return Err(ModuleErr::ENOEXEC);
            }
        };
        if check_overflow && ovf {
            log::error!("Overflow detected during relocation type {:?}", self);
            return Err(ModuleErr::ENOEXEC);
        }
        Ok(())
    }
}

pub struct ArchRelocate;

#[allow(unused_assignments)]
impl ArchRelocate {
    /// See <https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/kernel/module.c#L344>
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

            // loc corresponds to P in the AArch64 ELF document.
            let location = sechdrs[rel_section.sh_info as usize].sh_addr + rela.r_offset;
            let (sym, sym_name) = &load_info.syms[sym_idx];

            let reloc_type = Arm64RelTy::try_from(rel_type).map_err(|_| {
                log::error!(
                    "[{:?}]: Invalid relocation type: {}",
                    module.name(),
                    rel_type
                );
                ModuleErr::ENOEXEC
            })?;
            // val corresponds to (S + A) in the AArch64 ELF document.
            let target_addr = sym.st_value.wrapping_add(rela.r_addend as u64);

            // Perform the static relocation.
            log::info!(
                "[{:?}]: Applying relocation {:?} at location {:#x} with target addr {:#x}",
                module.name(),
                reloc_type,
                location,
                target_addr
            );

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

pub fn module_frob_arch_sections<H: KernelModuleHelper>(
    elf: &mut Elf,
    owner: &mut ModuleOwner<H>,
) -> Result<()> {
    let mut num_plts = 0usize;
    let mut num_gots = 0usize;

    for (idx, rela_sec) in elf.shdr_relocs.iter() {
        let shdr = &elf.section_headers[*idx];
        if shdr.sh_type != goblin::elf::section_header::SHT_RELA {
            continue;
        }

        let to_section = &elf.section_headers[shdr.sh_info as usize];
        if to_section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 == 0 {
            continue;
        }

        num_plts += count_plts(rela_sec);
        num_gots += count_gots(rela_sec);
    }

    if num_plts == 0 && num_gots == 0 {
        return Ok(());
    }

    common_prepare_got_section(
        elf,
        &mut owner.arch.got,
        num_gots,
        core::mem::align_of::<GotEntry>() as u64,
        0,
    )?;

    // Linux reserves module PLT entries before final layout.
    // https://codebrowser.dev/linux/linux/arch/arm64/kernel/module-plts.c.html#337
    common_prepare_plt_section::<PltEntry>(elf, &mut owner.arch.plt, num_plts, 4, 0)?;

    Ok(())
}

fn count_plts(rela_sec: &RelocSection) -> usize {
    rela_sec
        .iter()
        .filter(|rela| {
            matches!(
                Arm64RelTy::try_from(rela.r_type),
                Ok(Arm64RelTy::R_AARCH64_CALL26 | Arm64RelTy::R_AARCH64_JUMP26)
            )
        })
        .count()
}

fn count_gots(rela_sec: &RelocSection) -> usize {
    rela_sec
        .iter()
        .filter(|rela| {
            matches!(
                Arm64RelTy::try_from(rela.r_type),
                Ok(Arm64RelTy::R_AARCH64_ADR_GOT_PAGE | Arm64RelTy::R_AARCH64_LD64_GOT_LO12_NC)
            )
        })
        .count()
}
