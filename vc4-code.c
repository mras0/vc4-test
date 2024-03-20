#include <stdint.h>

#define IC0_VADDR       (*(volatile uint32_t*)0x7e002030) 
#define IC1_VADDR       (*(volatile uint32_t*)0x7e002830) 
#define IC1_WAKEUP      (*(volatile uint32_t*)0x7e002834) 
#define ST_CLO		(*(const volatile uint32_t*)0x7e003004)

volatile uint32_t* volatile g_mem;

static void delay(uint32_t cnt)
{
	// ST_CLO seems to tick once every 200 instructions (or maybe it's exactly 100 and it can dual issue)
	while (cnt--) {
		const uint32_t c = ST_CLO;
		while (c == ST_CLO)
			asm volatile("nop");
	}
}

// Bit16 is core number
static uint32_t chipid(void)
{
	uint32_t id;
	asm volatile ("version %0" : "=r" (id));
	return id;
}

static void test_func(void)
{
	g_mem[8] = chipid();
	for (;;) {
		g_mem[9]++;
		asm volatile ("sleep");
	}
}

static inline uint32_t read_PRPOWCTL(void)
{
	uint32_t id;
	asm volatile ("mov.m %0,p10" : "=r" (id));
	return id;
}

static inline void write_PRPOWCTL(uint32_t val)
{
	asm volatile ("mov.m p10,%0" : : "r" (val));
}


uint32_t _start(uint32_t* mem)
{
	g_mem = mem;
	g_mem[0] = chipid();
	g_mem[1] = IC0_VADDR;
	g_mem[2] = IC1_VADDR;
	//g_mem[3] = IC1_WAKEUP;
	//delay(10);
	return chipid();
}
