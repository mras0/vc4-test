#ifndef VC4_H
#define VC4_H

#include <stdint.h>

enum {
	MEM_FLAG_DISCARDABLE = 1 << 0, /* can be resized to 0 at any time. Use for cached data */
	MEM_FLAG_NORMAL = 0 << 2, /* normal allocating alias. Don't use from ARM */
	MEM_FLAG_DIRECT = 1 << 2, /* 0xC alias uncached */
	MEM_FLAG_COHERENT = 2 << 2, /* 0x8 alias. Non-allocating in L2 but coherent */
	MEM_FLAG_L1_NONALLOCATING = (MEM_FLAG_DIRECT | MEM_FLAG_COHERENT), /* Allocating in L2 */
	MEM_FLAG_ZERO = 1 << 4,  /* initialise buffer to all zeros */
	MEM_FLAG_NO_INIT = 1 << 5, /* don't initialise (default is initialise to all ones */
	MEM_FLAG_HINT_PERMALOCK = 1 << 6, /* Likely to be locked for long periods of time. */
};

typedef struct vc4_mem {
	unsigned size;
	unsigned handle;
	unsigned busaddr;
	void* hostptr;
} vc4_mem;

int vc4_init(void);
void vc4_free(void);

int vc4_mem_alloc(vc4_mem* m, unsigned size);
void vc4_mem_free(vc4_mem* m);
int vc4_run_vpu1(uint32_t entry, uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4, uint32_t r5);

#endif
