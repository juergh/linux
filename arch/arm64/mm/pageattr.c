/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

static int change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr,
			void *data)
{
	struct page_change_data *cdata = data;
	pte_t pte = *ptep;

	pte = clear_pte_bit(pte, cdata->clear_mask);
	pte = set_pte_bit(pte, cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

static int change_memory_common(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr;
	unsigned long size = PAGE_SIZE*numpages;
	unsigned long end = start + size;
	int ret;
	struct page_change_data data;

	if (!IS_ALIGNED(addr, PAGE_SIZE)) {
		start &= PAGE_MASK;
		end = start + size;
		WARN_ON_ONCE(1);
	}

	if (start < MODULES_VADDR || start >= MODULES_END)
		return -EINVAL;

	if (end < MODULES_VADDR || end >= MODULES_END)
		return -EINVAL;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret = apply_to_page_range(&init_mm, start, size, change_page_range,
					&data);

	flush_tlb_kernel_range(start, end);
	return ret;
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_RDONLY),
					__pgprot(PTE_WRITE));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_WRITE),
					__pgprot(PTE_RDONLY));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_PXN),
					__pgprot(0));
}
EXPORT_SYMBOL_GPL(set_memory_nx);

int set_memory_x(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(0),
					__pgprot(PTE_PXN));
}
EXPORT_SYMBOL_GPL(set_memory_x);


#ifdef CONFIG_XPFO

static inline int need_extra_page(unsigned long addr, size_t size)
{
	if(((addr + size) & PAGE_MASK) != (addr & PAGE_MASK)){
		BUG_ON((size > PAGE_SIZE));
		return 1;
	}
	return 0;
}

enum dma_operation {MAP, UNMAP};

static inline void xpfo_dma_ops(enum dma_operation op, const void *kaddr, size_t size, int dir)
{
	unsigned long flags;
	unsigned long __kaddr;
	struct page *pg;
	int extra_page = 0;
	void *buffer1 = NULL;
	void *buffer2 = NULL;
	
	/* How many pages will we need map?: assume worst case un-alinged PAGE_SIZE size for now */
	
	__kaddr = (unsigned long)kaddr;
	
	local_irq_save(flags);
	
	extra_page = need_extra_page(__kaddr, size);
	
	pg =  pfn_to_page(PFN_DOWN(virt_to_phys((void *)__kaddr)));
	
	if(PageUser(pg))
		buffer1 = kmap_atomic(pg);
	
	if(extra_page && PageUser(pg+1))
		buffer2 = kmap_atomic(pg+1);
	
	switch(op)
	{
	case MAP:
		__dma_map_area(kaddr, size, dir);
		break;
	case UNMAP:
		__dma_unmap_area(kaddr, size, dir);
		break;
	default:
		printk(KERN_ERR "__xpfo_dma_ops: unhandled OP type (%u)\n", op);
		BUG();
	}
	
	if(buffer1)
		kunmap_atomic(buffer1);
	
	if(buffer2)
		kunmap_atomic(buffer2);
	
	local_irq_restore(flags);
}
		

inline void xpfo_dma_map_area(const void *kaddr, size_t size, int dir)
{
	xpfo_dma_ops(MAP, kaddr, size, dir);
}

	
inline void xpfo_dma_unmap_area(const void *kaddr, size_t size, int dir)
{
	xpfo_dma_ops(UNMAP, kaddr, size, dir);
}


/* lookup_address() based on x86 tree
 *
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry.
 */
pte_t *lookup_address(unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(&init_mm, address);


	if (pgd_none(*pgd))
		return NULL;

	BUG_ON(pgd_bad(*pgd));

	pud = pud_offset(pgd, address);

#if 0
	/* We assume section mappings are disabled for now. Need to re-visit
	 * once we can re-enable the use of section mappings 
	 */
	
	if (pud_none(*pud) || pud_sect(*pud))
		return NULL;

	BUG_ON(pud_bad(*pud));
	
	pmd = pmd_offset(pud, address);
	
	if (pmd_none(*pmd) || pmd_sect(*pmd)) 
		return NULL;

#else
	if (pud_none(*pud))
		return NULL;

	BUG_ON(pud_bad(*pud));
	
	pmd = pmd_offset(pud, address);
	
	if (pmd_none(*pmd))
		return NULL;
#endif
	BUG_ON(pmd_bad(*pmd));
	
	pte = pte_offset_kernel(pmd, address);

	return pte;
}


/*
 * Atomic update of a single, kernel page table entry.
 *
 * @pg:		page frame to map/unmap
 * @kaddr:	kernel address of `pg' (in the direct-mapped memory region)
 * @prot:	protection flags
 */


inline void
set_kpte(struct page *pg, unsigned long kaddr, pgprot_t prot)
{
	pte_t		*kptep;
	pte_t           kpte;
	
	kptep = lookup_address(kaddr);

	/* TODO: remove (sanity check) */
	BUG_ON(!kptep);

	kpte = pfn_pte(page_to_pfn(pg), prot);
	
	set_pte(kptep, kpte);

}

/*
 * Exclusive page frame ownership (XPFO).
 *
 * @act:	command/action (alloc, free, map, unmap ...)
 * @kaddr:	kernel address (of `pg')
 * @pg:		page frame (starting page frame if num > 1)
 * @num:	number of (consecutive) page frames
 */
void
xpfo_ctl(xpfo_cmd_t act, void *kaddr, struct page *pg, int num)
{
	int i, tlb_shoot = 0;
	unsigned long __kaddr = (unsigned long)kaddr;
	
	switch (act) {
		/* page frame(s) allocated (destined to kernel space) */
		case XPFO_CMD_KALLOC:
			for (i = 0; i < num; i++)  {
				/* TODO: remove (sanity check) */
				WARN_ON(PageUserFp(pg + i) || PageUser(pg + i));
			
				/* enable XPFO on the page frame */
				__SetPageKernel(pg + i);
			}
			
			/* done */
			break;

		/* page frame(s) allocated (destined to user space) */
		case XPFO_CMD_UALLOC:
			for (i = 0; i < num; i++)  {
				/* TODO: remove (sanity check) */
				WARN_ON(PageUserFp(pg + i) || PageUser(pg + i));
				
				/* enable XPFO on the page frame */
				__SetPageUserFp(pg + i);
					
				/* set the map counter */
				xpfo_kmcnt_init(pg + i);

				/* initialize the per-page frame lock */
				xpfo_lock_init(pg + i);
				
				/*
				 * the page frame was previously
				 * allocated to kernel space
				 */
				if (__TestClearPageKernel(pg + i))
					/* enable TLB shootdown */
					tlb_shoot = 1;
			}

			/* perform TLB shootdown */
			if (tlb_shoot){
				flush_tlb_kernel_range(__kaddr,
						__kaddr + (num * PAGE_SIZE));
			}
			/* done */
			break;

		/* page frame(s) deallocated */
		case XPFO_CMD_FREE:
			for (	i = 0;
				i < num;
				i++, __kaddr += PAGE_SIZE, kaddr += PAGE_SIZE) {
				/*
				 * the page frame was previously
				 * allocated to user space
				 */
				if (__TestClearPageUser(pg + i)) {
				        /* map it back to kernel space */
					set_kpte(pg + i,
						__kaddr,
						__pgprot(PAGE_KERNEL));
					/* no TLB update */

					/* zap the contents of the page frame */
					clear_page(kaddr);
					
					/* mark it accordingly (clean) */
					__SetPageZap(pg + i);
				}
				/* reset XPFO */
				__ClearPageUserFp(pg + i);
			}

			/* done */
			break;

		/* page frame (needs to be) mapped to kernel space */
		case XPFO_CMD_KMAP:
			/* TODO: remove (sanity check) */	
			BUG_ON(num != 1);
				
			/* the page is allocated to kernel space */
			if (PageKernel(pg))
				/* done; fast path */
				break;
			
			/* get the per-page frame lock */
			xpfo_lock(pg);

			/* the page was previously allocated to user space */
			if (xpfo_kmcnt_get(pg) && PageUser(pg)){
                                /* map it to kernel space */
				set_kpte(pg, __kaddr, __pgprot(PAGE_KERNEL));
			}
			/* no TLB update */

			/* release the per-page frame lock */
			xpfo_unlock(pg);
			
			/* done */
			break;

		/* page frame (needs to be) unmaped from kernel space */
		case XPFO_CMD_KUNMAP:
			/* TODO: remove (sanity check) */
			BUG_ON(num != 1);
			
			/* the page is allocated to kernel space */
			if (PageKernel(pg))
				/* done; fast path */
				break;
			
			/* get the per-page frame lock */
			xpfo_lock(pg);

			/* the page frame is to be allocated to user space */
			if (xpfo_kmcnt_put(pg) 	&&
				(PageUserFp(pg) || PageUser(pg))) { 

                                /* unmap it from kernel space */
				set_kpte(pg, __kaddr, __pgprot(0));
				
				/* local TLB update */
				flush_tlb_kernel_one(__kaddr);

				/* mark it accordingly (user) */
				__SetPageUser(pg);
			}
			
			/* release the per-page frame lock */
			xpfo_unlock(pg);
			
			/* done */
			break;

		default:	/* sanity check */
			BUG();

			break;	/* make the compiler happy */
	}
}
EXPORT_SYMBOL(xpfo_ctl);
EXPORT_SYMBOL(xpfo_dma_map_area);
EXPORT_SYMBOL(xpfo_dma_unmap_area);
#endif /* CONFIG_XPFO */
