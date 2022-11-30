// SPDX-License-Identifier: GPL-2.0-only
/*
 * Extensible Firmware Interface
 *
 * Based on Extensible Firmware Interface Specification version 2.4
 *
 * Copyright (C) 2013, 2014 Linaro Ltd.
 */

#include <linux/efi.h>
#include <linux/init.h>

#include <asm/efi.h>

/*
 * Only regions of type EFI_RUNTIME_SERVICES_CODE need to be
 * executable, everything else can be mapped with the XN bits
 * set. Also take the new (optional) RO/XP bits into account.
 */
static __init pteval_t create_mapping_protection(efi_memory_desc_t *md)
{
	u64 attr = md->attribute;
	u32 type = md->type;

	if (type == EFI_MEMORY_MAPPED_IO)
		return PROT_DEVICE_nGnRE;

	if (WARN_ONCE(!PAGE_ALIGNED(md->phys_addr),
		      "UEFI Runtime regions are not aligned to 64 KB -- buggy firmware?"))
		/*
		 * If the region is not aligned to the page size of the OS, we
		 * can not use strict permissions, since that would also affect
		 * the mapping attributes of the adjacent regions.
		 */
		return pgprot_val(PAGE_KERNEL_EXEC);

	/* R-- */
	if ((attr & (EFI_MEMORY_XP | EFI_MEMORY_RO)) ==
	    (EFI_MEMORY_XP | EFI_MEMORY_RO))
		return pgprot_val(PAGE_KERNEL_RO);

	/* R-X */
	if (attr & EFI_MEMORY_RO)
		return pgprot_val(PAGE_KERNEL_ROX);

	/* RW- */
	if (((attr & (EFI_MEMORY_RP | EFI_MEMORY_WP | EFI_MEMORY_XP)) ==
	     EFI_MEMORY_XP) ||
	    type != EFI_RUNTIME_SERVICES_CODE)
		return pgprot_val(PAGE_KERNEL);

	/* RWX */
	return pgprot_val(PAGE_KERNEL_EXEC);
}

static u64 __initdata max_virt_addr;

efi_status_t (* efi_rt_asm_wrapper)(void *, const char *, ...) __ro_after_init;

static int __init efi_map_rt_wrapper(void)
{
	extern const __le32 __efi_rt_asm_wrapper[];

	u64 phys_base = __pa_symbol(__efi_rt_asm_wrapper) & PAGE_MASK;
	u64 virt_base = max_virt_addr ?: phys_base;
	u64 offset = virt_base - phys_base;
	pgprot_t prot = PAGE_KERNEL_ROX;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	/*
	 * Map the EFI runtime call wrapper routine into the EFI page tables at
	 * a virtual address that is known to be available: either 1:1 if that
	 * is what EFI is doing as well, or at the lowest unused VA above the
	 * existing runtime services mappings otherwise.
	 */
	pgprot_val(prot) |= PTE_MAYBE_GP;
	create_pgd_mapping(&efi_mm, phys_base, virt_base, 2 * PAGE_SIZE, prot,
			   false);

	efi_rt_asm_wrapper = (void *)__pa_symbol(__efi_rt_asm_wrapper) + offset;
	return 0;
}
core_initcall(efi_map_rt_wrapper);

/* we will fill this structure from the stub, so don't put it in .bss */
struct screen_info screen_info __section(".data");
EXPORT_SYMBOL(screen_info);

int __init efi_create_mapping(struct mm_struct *mm, efi_memory_desc_t *md)
{
	pteval_t prot_val = create_mapping_protection(md);
	bool page_mappings_only = (md->type == EFI_RUNTIME_SERVICES_CODE ||
				   md->type == EFI_RUNTIME_SERVICES_DATA);

	if (!PAGE_ALIGNED(md->phys_addr) ||
	    !PAGE_ALIGNED(md->num_pages << EFI_PAGE_SHIFT)) {
		/*
		 * If the end address of this region is not aligned to page
		 * size, the mapping is rounded up, and may end up sharing a
		 * page frame with the next UEFI memory region. If we create
		 * a block entry now, we may need to split it again when mapping
		 * the next region, and support for that is going to be removed
		 * from the MMU routines. So avoid block mappings altogether in
		 * that case.
		 */
		page_mappings_only = true;
	}

	create_pgd_mapping(mm, md->phys_addr, md->virt_addr,
			   md->num_pages << EFI_PAGE_SHIFT,
			   __pgprot(prot_val | PTE_NG), page_mappings_only);

	// capture the top of the occupied VA space if not using a 1:1 mapping
	if (md->virt_addr != md->phys_addr) {
		u64 top = PAGE_ALIGN(md->virt_addr +
				     (md->num_pages << EFI_PAGE_SHIFT));

		max_virt_addr = max(max_virt_addr, top);
	}
	return 0;
}

static int __init set_permissions(pte_t *ptep, unsigned long addr, void *data)
{
	efi_memory_desc_t *md = data;
	pte_t pte = READ_ONCE(*ptep);

	if (md->attribute & EFI_MEMORY_RO)
		pte = set_pte_bit(pte, __pgprot(PTE_RDONLY));
	if (md->attribute & EFI_MEMORY_XP)
		pte = set_pte_bit(pte, __pgprot(PTE_PXN));
	set_pte(ptep, pte);
	return 0;
}

int __init efi_set_mapping_permissions(struct mm_struct *mm,
				       efi_memory_desc_t *md)
{
	BUG_ON(md->type != EFI_RUNTIME_SERVICES_CODE &&
	       md->type != EFI_RUNTIME_SERVICES_DATA);

	/*
	 * Calling apply_to_page_range() is only safe on regions that are
	 * guaranteed to be mapped down to pages. Since we are only called
	 * for regions that have been mapped using efi_create_mapping() above
	 * (and this is checked by the generic Memory Attributes table parsing
	 * routines), there is no need to check that again here.
	 */
	return apply_to_page_range(mm, md->virt_addr,
				   md->num_pages << EFI_PAGE_SHIFT,
				   set_permissions, md);
}

/*
 * UpdateCapsule() depends on the system being shutdown via
 * ResetSystem().
 */
bool efi_poweroff_required(void)
{
	return efi_enabled(EFI_RUNTIME_SERVICES);
}

asmlinkage efi_status_t efi_handle_corrupted_x18(efi_status_t s, const char *f)
{
	pr_err_ratelimited(FW_BUG "register x18 corrupted by EFI %s\n", f);
	return s;
}
