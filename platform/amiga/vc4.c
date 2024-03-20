#include "platform/vc4.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <exec/types.h>
#include <proto/exec.h>
#include "devicetree.h"

#define BUS_TO_PHYS(x) ((x)&~0xC0000000)

#define MAX_COMMAND_LENGTH 32

static APTR DeviceTreeBase;
static ULONG MailBox;
static uint32_t MBReqStorage[MAX_COMMAND_LENGTH + 4];
static uint32_t* MBReq;

#define LE32(x) (__builtin_bswap32(x))

#define MBOX_READ   LE32(*((const volatile uint32_t*)(MailBox + 0x00)))
#define MBOX_STATUS LE32(*((const volatile uint32_t*)(MailBox + 0x18)))
#define MBOX_WRITE  *((volatile uint32_t*)(MailBox + 0x20))

#define MBOX_CHANNEL 8

#define MBOX_TX_FULL (1UL << 31)
#define MBOX_RX_EMPTY (1UL << 30)
#define MBOX_CHANMASK 0xF

// TODO: We need "mailbox.resource" or similar

static uint32_t mbox_recv(void)
{
    uint32_t rsp;
    do {
        while (MBOX_STATUS & MBOX_RX_EMPTY)
            asm volatile("nop");

        asm volatile("nop");
        rsp = MBOX_READ;
        asm volatile("nop");
    } while ((rsp & MBOX_CHANMASK) != MBOX_CHANNEL);
    asm volatile ("nop" ::: "memory");
    return rsp & ~MBOX_CHANMASK;
}

static void mbox_send(uint32_t* req)
{
    CacheClearE(req, __builtin_bswap32(*req), CACRF_ClearD);
    while (MBOX_STATUS & MBOX_TX_FULL)
        asm volatile ("nop");
    asm volatile ("nop");
    MBOX_WRITE = LE32(((uint32_t)req & ~MBOX_CHANMASK) | MBOX_CHANNEL);
}

static int mbox_transaction(uint32_t* req)
{
    mbox_send(req);
    mbox_recv();
    if (LE32(req[1]) == 0x80000000)
        return 0;
    //fprintf(stderr, "Mailbox transaction failed for command %08x: %08x\n", LE32(req[2]), LE32(req[1]));
    return LE32(req[1]);
}

static unsigned mem_alloc(unsigned size, unsigned align, unsigned flags)
{
   int i=0;
   uint32_t* p = MBReq;
   p[i++] = 0; // size
   p[i++] = 0; // process request

   p[i++] = LE32(0x3000c); // (the tag id)
   p[i++] = LE32(12); // (size of the buffer)
   p[i++] = LE32(12); // (size of the data)
   p[i++] = LE32(size); // (num bytes? or pages?)
   p[i++] = LE32(align); // (alignment)
   p[i++] = LE32(flags); // (MEM_FLAG_L1_NONALLOCATING)

   p[i++] = 0; // end tag
   p[0] = LE32(i*sizeof *p); // actual size

   if (mbox_transaction(p))
       return 0;
   return LE32(p[5]);
}

static unsigned mem_free(unsigned handle)
{
   int i=0;
   uint32_t* p = MBReq;
   p[i++] = 0; // size
   p[i++] = 0; // process request

   p[i++] = LE32(0x3000f); // (the tag id)
   p[i++] = LE32(4); // (size of the buffer)
   p[i++] = LE32(4); // (size of the data)
   p[i++] = LE32(handle);

   p[i++] = 0; // end tag
   p[0] = LE32(i*sizeof *p); // actual size

   if (mbox_transaction(p))
       return -1;
   return LE32(p[5]);
}

static unsigned mem_lock(unsigned handle)
{
   int i=0;
   uint32_t* p = MBReq;
   p[i++] = 0; // size
   p[i++] = 0; // process request
   p[i++] = LE32(0x3000d); // (the tag id)
   p[i++] = LE32(4); // (size of the buffer)
   p[i++] = LE32(4); // (size of the data)
   p[i++] = LE32(handle);

   p[i++] = 0; // end tag
   p[0] = LE32(i*sizeof *p); // actual size

   if (mbox_transaction(p))
       return 0;
   return LE32(p[5]);
}

static unsigned mem_unlock(unsigned handle)
{
   int i=0;
   uint32_t* p = MBReq;
   p[i++] = 0; // size
   p[i++] = 0; // process request

   p[i++] = LE32(0x3000e); // (the tag id)
   p[i++] = LE32(4); // (size of the buffer)
   p[i++] = LE32(4); // (size of the data)
   p[i++] = LE32(handle);

   p[i++] = 0; // end tag
   p[0] = LE32(i*sizeof *p); // actual size

   if (mbox_transaction(p))
       return -1;
   return LE32(p[5]);
}

static unsigned execute_code_vpu1(unsigned code, unsigned r0, unsigned r1, unsigned r2, unsigned r3, unsigned r4, unsigned r5)
{
   int i=0;
   uint32_t* p = MBReq;
   p[i++] = 0; // size
   p[i++] = 0; // process request

   p[i++] = LE32(0x30013); // (the tag id)
   p[i++] = LE32(28); // (size of the buffer)
   p[i++] = LE32(28); // (size of the data)
   p[i++] = LE32(code);
   p[i++] = LE32(r0);
   p[i++] = LE32(r1);
   p[i++] = LE32(r2);
   p[i++] = LE32(r3);
   p[i++] = LE32(r4);
   p[i++] = LE32(r5);

   p[i++] = 0; // end tag
   p[0] = LE32(i*sizeof *p); // actual size

   if ((i = mbox_transaction(p)) != 0)
	   fprintf(stderr, "Failed to execute code! %08x\n", i);
   return p[5];
}


/*
    Some properties, like e.g. #size-cells, are not always available in a key, but in that case the properties
    should be searched for in the parent. The process repeats recursively until either root key is found
    or the property is found, whichever occurs first
*/
static CONST_APTR GetPropValueRecursive(APTR key, CONST_STRPTR property)
{
    do {
        /* Find the property first */
        APTR prop = DT_FindProperty(key, property);

        if (prop)
        {
            /* If property is found, get its value and exit */
            return DT_GetPropValue(prop);
        }
        
        /* Property was not found, go to the parent and repeat */
        key = DT_GetParent(key);
    } while (key);

    return NULL;
}


int vc4_init(void)
{
    MBReq = (uint32_t*)(((uintptr_t)MBReqStorage + 15) & ~15);
    if ((DeviceTreeBase = OpenResource("devicetree.resource")) != NULL) {
        APTR key = DT_OpenKey("/aliases");
        if (key) {
            const char* mbox_alias = DT_GetPropValue(DT_FindProperty(key, "mailbox"));
            DT_CloseKey(key);
            if (mbox_alias) {
                key = DT_OpenKey(mbox_alias);
                if (key) {
					//ULONG size_cells = 1;
					ULONG address_cells = 1;
					
					//CONST ULONG *siz = GetPropValueRecursive(key, "#size_cells");
					CONST ULONG *adr = GetPropValueRecursive(key, "#address-cells");
					CONST ULONG *reg = DT_GetPropValue(DT_FindProperty(key, "reg"));
					
					//if (siz != NULL) size_cells = *siz;
					if (adr != NULL) address_cells = *adr;
					MailBox = reg[(1 * address_cells) - 1];
                    DT_CloseKey(key);

                    /* Open /soc key and learn about VC4 to CPU mapping. Use it to adjust the addresses obtained above */
                    key = DT_OpenKey("/soc");
                    if (key) {
                        address_cells = 1;
                        ULONG cpu_address_cells = 1;

                        //const ULONG * siz = GetPropValueRecursive(key, "#size_cells");
                        const ULONG * addr = GetPropValueRecursive(key, "#address-cells");
                        const ULONG * cpu_addr = DT_GetPropValue(DT_FindProperty(DT_OpenKey("/"), "#address-cells"));

                        //if (siz != NULL) size_cells = *siz;
                        if (addr != NULL) address_cells = *addr;
                        if (cpu_addr != NULL) cpu_address_cells = *cpu_addr;

                        const ULONG *reg = DT_GetPropValue(DT_FindProperty(key, "ranges"));

                        ULONG phys_vc4 = reg[address_cells - 1];
                        ULONG phys_cpu = reg[address_cells + cpu_address_cells - 1];

                        MailBox = ((ULONG)MailBox - phys_vc4 + phys_cpu);

                        DT_CloseKey(key);
                    } else {
                        printf("Could not open /soc\n");
                        MailBox = 0;
                    }
                } else {
                    printf("Could not open mail box alias\n");
                }
            } else {
                printf("Not mailbox alias\n");
            }
        } else {
            printf("Could not open aliases\n");
        }
    } else {
        printf("Could not open devicetree.resource\n");
    }
    return MailBox ? 0 : -1;
}

void vc4_free(void)
{
}


void vc4_mem_free(vc4_mem* m)
{
	if (m->handle) {
		if (m->busaddr)
			mem_unlock(m->handle);
		mem_free(m->handle);
	}
	memset(m, 0, sizeof(*m));
}

int vc4_mem_alloc(vc4_mem* m, unsigned size)
{
	memset(m, 0, sizeof(*m));
    const uint32_t align = 16;
	m->size = (size + align - 1) & ~(align - 1);
	m->handle = mem_alloc(m->size, 8, MEM_FLAG_DIRECT);
	if (!m->handle) {
		fprintf(stderr, "Failed to alloc mem\n");
		return -1;
	}
	m->busaddr = mem_lock(m->handle);
	if (!m->busaddr) {
		fprintf(stderr, "Failed to lock memory\n");
		vc4_mem_free(m);
		return -1;
	}
	m->hostptr = (void*)BUS_TO_PHYS(m->busaddr);
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
    return execute_code_vpu1(entry, r0, r1, r2, r3, r4, r5);
}
