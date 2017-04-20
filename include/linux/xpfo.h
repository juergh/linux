#ifndef _LINUX_XPFO_H
#define _LINUX_XPFO_H

typedef enum {
	XPFO_CMD_UALLOC = 1,	/* user space page frame allocation	*/
	XPFO_CMD_KALLOC,	/* kernel space page frame allocation	*/
	XPFO_CMD_FREE,		/* page frame deallocation		*/
	XPFO_CMD_KMAP,		/* page frame mapping (kernel space)	*/
	XPFO_CMD_KUNMAP		/* page frame unmapping (kernel space)	*/	
} xpfo_cmd_t;

#ifdef CONFIG_XPFO
typedef enum {
	PG_user_fp = 0,	/* page frame allocated to user space (fast path) */
	PG_user,	/* page frame allocated to user space		  */
	PG_kernel,	/* page frame allocated to kernel space		  */
	PG_zap,		/* clean page frame				  */
} xpfo_gpf_t; 

/* get the value of `PG_user_fp' */
static inline int PageUserFp(struct page *page)
{
	return test_bit(PG_user_fp, &page->xpfo_flags);
}

/* assert `PG_user_fp' */
static inline void __SetPageUserFp(struct page *page)
{
	__set_bit(PG_user_fp, &page->xpfo_flags);
}

/* clear `PG_user_fp' */
static inline void __ClearPageUserFp(struct page *page)
{
	__clear_bit(PG_user_fp, &page->xpfo_flags);
}

/* get the value of `PG_user' */
static inline int PageUser(struct page *page)
{
	return test_bit(PG_user, &page->xpfo_flags);
}

/* assert `PG_user' */
static inline void __SetPageUser(struct page *page)
{
	__set_bit(PG_user, &page->xpfo_flags);
}

/* get the value `PG_user' and clear it afterwards */
static inline int __TestClearPageUser(struct page *page)
{
	return __test_and_clear_bit(PG_user, &page->xpfo_flags);
}

/* get the value of `PG_kernel' */
static inline int PageKernel(struct page *page)
{
	return test_bit(PG_kernel, &page->xpfo_flags);
}

/* assert `PG_kernel' */
static inline void __SetPageKernel(struct page *page)
{
	__set_bit(PG_kernel, &page->xpfo_flags);
}

/* get the value `PG_kernel' and clear it afterwards */
static inline int __TestClearPageKernel(struct page *page)
{
	return __test_and_clear_bit(PG_kernel, &page->xpfo_flags);
}

/* get the value of `PG_zap' */
static inline int PageZap(struct page *page)
{
	return test_bit(PG_zap, &page->xpfo_flags);
}

/* assert `PG_zap' */
static inline void __SetPageZap(struct page *page)
{
	__set_bit(PG_zap, &page->xpfo_flags);
}

/* clear `PG_zap' */
static inline void __ClearPageZap(struct page *page)
{
	__clear_bit(PG_zap, &page->xpfo_flags);
}

/* get the value `PG_zap' and clear it afterwards */
static inline int __TestClearPageZap(struct page *page)
{
	return __test_and_clear_bit(PG_zap, &page->xpfo_flags);
}

static inline void xpfo_kmcnt_init(struct page *page)
{
	atomic_set(&page->xpfo_kmcnt, 0);
}

static inline int xpfo_kmcnt_get(struct page *page)
{
	return (atomic_inc_return(&page->xpfo_kmcnt) == 1);
}

static inline int xpfo_kmcnt_put(struct page *page)
{
	return (atomic_dec_return(&page->xpfo_kmcnt) == 0);
}

static inline void xpfo_lock_init(struct page *page)
{
	spin_lock_init(&page->xpfo_lock);
}

static inline void xpfo_lock(struct page *page)
{
	spin_lock(&page->xpfo_lock);
}

static inline void xpfo_unlock(struct page *page)
{
	spin_unlock(&page->xpfo_lock);
}

extern void xpfo_ctl(xpfo_cmd_t act, void *kaddr, struct page *pg, int num);
extern void xpfo_dma_map_area(const void *, size_t, int);
extern void xpfo_dma_unmap_area(const void *, size_t, int);
#else
static inline int PageKernel(struct page *page) { return 0; }
static inline int PageZap(struct page *page) { return 0; }
static inline void __ClearPageZap(struct page *page) { }
static inline int __TestClearPageZap(struct page *page) { return 0; }
static inline void xpfo_ctl(xpfo_cmd_t act, void *kaddr, struct page *pg, int num) { }
static inline int PageUser(struct page *page){ return 0; }
static inline void MapPageUser(const void *kaddr, size_t size, unsigned long *flags) { }
static inline void UnmapPageUser(const void *kaddr, size_t size, unsigned long *flags) { }
#define xpfo_dma_map_area __dma_map_area
#define xpfo_dma_unmap_area __dma_unmap_area
#endif

#endif	/* _LINUX_XPFO_H */
