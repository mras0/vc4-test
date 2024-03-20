#include "mailbox.h"
#include "platform/vc4.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUS_TO_PHYS(x) ((x)&~0xC0000000)

static int mbox;

int vc4_init(void)
{
	mbox = mbox_open();
	if (mbox < 0) {
		mbox = 0;
		return -1;
	}
	return 0;
}

void vc4_free(void)
{
	if (mbox)
		mbox_close(mbox);
	mbox = 0;
}

void vc4_mem_free(vc4_mem* m)
{
	if (m->handle) {
		if (m->hostptr)
			unmapmem(m->hostptr, m->size);
		if (m->busaddr)
			mem_unlock(mbox, m->handle);
		mem_free(mbox, m->handle);
	}
	memset(m, 0, sizeof(*m));
}

int vc4_mem_alloc(vc4_mem* m, unsigned size)
{
	memset(m, 0, sizeof(*m));
	const unsigned page_size = sysconf(_SC_PAGESIZE);
	m->size = (size + page_size - 1) & ~(page_size - 1);
	m->handle = mem_alloc(mbox, m->size, 8, MEM_FLAG_DIRECT);
	if (!m->handle) {
		fprintf(stderr, "Failed to alloc mem\n");
		return -1;
	}
	m->busaddr = mem_lock(mbox, m->handle);
	if (!m->busaddr) {
		fprintf(stderr, "Failed to lock memory\n");
		vc4_mem_free(m);
		return -1;
	}
	m->hostptr = mapmem(BUS_TO_PHYS(m->busaddr), m->size);
	if (!m->hostptr) {
		fprintf(stderr, "Failed to map memory\n");
		vc4_mem_free(m);
		return -1;
	}
	printf("Allocated %u bytes, busaddr = %x phys = %x\n", size, m->busaddr, BUS_TO_PHYS(m->busaddr));
	return 0;
}

int vc4_run_vpu1(uint32_t entry, uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4, uint32_t r5)
{
	return execute_code_vpu1(mbox, entry, r0, r1, r2, r3, r4, r5);
}
