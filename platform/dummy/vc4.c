#include "platform/vc4.h"
#include <stdio.h>
#include <stdlib.h>


int vc4_init(void)
{
    return 0;
}

void vc4_free(void)
{
}


int vc4_mem_alloc(vc4_mem* m, unsigned size)
{
    memset(m, 0, sizeof(*m));
    m->hostptr = malloc(size);
    if (!m->hostptr)
        return -1;
    m->size = size;
    m->busaddr = 0xC0000000;
    return 0;
}

void vc4_mem_free(vc4_mem* m)
{
    free(m->hostptr);
    memset(m, 0, sizeof(*m));
}

int vc4_run_vpu1(uint32_t entry, uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4, uint32_t r5)
{
    (void)r0;
    (void)r1;
    (void)r2;
    (void)r3;
    (void)r4;
    (void)r5;
    printf("Fake running code from %x\n", entry);
    return 0;
}
