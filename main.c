#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include "platform/vc4.h"

/////////////////////////////////////////////////////////////////////////////
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LE(x) (x)
#else
#define LE(x) (__typeof(x))(sizeof(x) == 4 ? __builtin_bswap32(x) : sizeof(x) == 2 ? __builtin_bswap16(x) : (x))
#endif

/////////////////////////////////////////////////////////////////////////////
static void* read_file(const char* filename, size_t* size)
{
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t* data = malloc(*size);
    if (!data) {
        fprintf(stderr, "Could not allocate %zu bytes\n", *size);
        fclose(fp);
        return NULL;
    }
    if (fread(data, 1, *size, fp) != *size) {
        fprintf(stderr, "Error reading from %s\n", filename);
        free(data);
        data = NULL;
    }
    fclose(fp);
    return data;
}

/////////////////////////////////////////////////////////////////////////////
#define EM_VIDEOCORE3      137

// vc4-toolchain/binutils-vc4/nclude/elf/vc4.h contains reloc numbers

#define R_VC4_NONE          0
#define R_VC4_PCREL7_MUL2   1
#define R_VC4_PCREL8_MUL2   2
#define R_VC4_PCREL10_MUL2  3
#define R_VC4_PCREL16       4
#define R_VC4_PCREL23_MUL2  5
#define R_VC4_PCREL27       6
#define R_VC4_PCREL27_MUL2  7
#define R_VC4_PCREL32       8
#define R_VC4_IMM5_MUL4     9
#define R_VC4_IMM5_1        10
#define R_VC4_IMM5_2        11
#define R_VC4_IMM6          12
#define R_VC4_IMM6_MUL4     13
#define R_VC4_IMM11         14
#define R_VC4_IMM12         15
#define R_VC4_IMM16         16
#define R_VC4_IMM23         17
#define R_VC4_IMM27         18
#define R_VC4_IMM32         19
#define R_VC4_IMM32_2       20
#define R_VC4_8             21
#define R_VC4_16            22
#define R_VC4_32            23

static const char* reloc_name(int type)
{
	switch (type) {
#define X_TYPE(t) case t: return #t;
	X_TYPE(R_VC4_NONE);
	X_TYPE(R_VC4_PCREL7_MUL2);
	X_TYPE(R_VC4_PCREL8_MUL2);
	X_TYPE(R_VC4_PCREL10_MUL2);
	X_TYPE(R_VC4_PCREL16);
	X_TYPE(R_VC4_PCREL23_MUL2);
	X_TYPE(R_VC4_PCREL27);
	X_TYPE(R_VC4_PCREL27_MUL2);
	X_TYPE(R_VC4_PCREL32);
	X_TYPE(R_VC4_IMM5_MUL4);
	X_TYPE(R_VC4_IMM5_1);
	X_TYPE(R_VC4_IMM5_2);
	X_TYPE(R_VC4_IMM6);
	X_TYPE(R_VC4_IMM6_MUL4);
	X_TYPE(R_VC4_IMM11);
	X_TYPE(R_VC4_IMM12);
	X_TYPE(R_VC4_IMM16);
	X_TYPE(R_VC4_IMM23);
	X_TYPE(R_VC4_IMM27);
	X_TYPE(R_VC4_IMM32);
	X_TYPE(R_VC4_IMM32_2);
	X_TYPE(R_VC4_8);
	X_TYPE(R_VC4_16);
	X_TYPE(R_VC4_32);
#undef X_TYPE
	}
	static char buf[64];
	snprintf(buf, sizeof(buf), "Unknown relocation type %d", type);
	return buf;
}

static const void* elf_section(const Elf32_Ehdr* ehdr, unsigned section)
{
	if (!section || section >= LE(ehdr->e_shnum))
		return NULL;

	return (const uint8_t*)ehdr + LE(ehdr->e_shoff) + sizeof(Elf32_Shdr) * section;
}

static const Elf32_Sym* elf_symbol(const Elf32_Ehdr* ehdr, int link, int symbol)
{
	if (!link || !symbol)
		return NULL;
	const Elf32_Shdr* s = elf_section(ehdr, link);
	if (symbol * LE(s->sh_entsize) >= LE(s->sh_size))
		return NULL;
	return &((const Elf32_Sym*)((const uint8_t*)ehdr + LE(s->sh_offset)))[symbol];
}

static inline uint16_t read_u16le(const void* p)
{
	const uint8_t* u8 = p;
	return u8[0] | u8[1] << 8;
}

static inline uint32_t read_u32le(const void* p)
{
	return read_u16le(p) | read_u16le((const uint8_t*)p + 2) << 16;
}

static inline void write_u16le(void* p, uint16_t val)
{
	uint8_t* u8 = p;
	u8[0] = (uint8_t)val;
	u8[1] = (uint8_t)(val >> 8);
}

static inline void write_u32le(void* p, uint32_t val)
{
	write_u16le(p, (uint16_t)val);
	write_u16le((uint8_t*)p + 2, (uint16_t)(val >> 16));
}

// Instruction stream consist of 16-bit little endian word values
// So layout of longer instructions is a bit weird, so a 32-bit instruction
// 0x12345678 is stored in memory as 34 12 78 56
// Scalar48 (0x12345678ABCD)  is stored as 34 12 CD AB 78 56 though!!!

static void print_inst(const uint8_t* c)
{
	uint16_t ins = read_u16le(c);
	for (int i = 16; i--; )
	       printf("%s%d", (i+1)%4 == 0 ? " " : "", (ins>>i)&1);
	int args = 0;
	if (ins & 0x8000) {
		if ((ins >> 12) == 0xf) {
			printf(" TODO!!\n");
		} else {
			args = 1;
		}
	}
	printf("\t %04X ", ins);
	for (int i = 0; i < args; ++i) {
		c += 2;
		ins = read_u16le(c);
		printf(" %04X", ins);
	}
	printf("\n");
}

static uint32_t read_ins32(const uint8_t* c)
{
	return read_u16le(c) << 16 | read_u16le(c + 2);
}

static void write_ins32(uint8_t* c, uint32_t val)
{
	write_u16le(c, (uint16_t)(val >> 16));
	write_u16le(c + 2, (uint16_t)val);
}

static uint32_t do_masked(uint32_t orig, uint32_t val, uint32_t bits)
{
	const uint32_t mask = (1 << bits) - 1;
	return (val & mask) | (orig & ~mask);
}

static void reloc_masked_u32(uint8_t* c, uint32_t val, uint32_t bits)
{
	write_u32le(c, do_masked(read_u32le(c), val, bits));
}

static void reloc_ins32(uint8_t* c, uint32_t val, uint32_t bits)
{
	write_ins32(c, do_masked(read_ins32(c), val, bits));
}

int vc4_elf_load(const char* filename, vc4_mem* vc_mem, uint32_t* entry_point)
{
    int ret = -1;
    size_t elf_size;
    uint8_t* elf = read_file(filename, &elf_size);
    if (!elf)
        goto out;

    const Elf32_Ehdr* ehdr = (const Elf32_Ehdr*)elf;
    if (elf_size < sizeof(*ehdr) || memcmp(ehdr, "\177ELF\001\001\001\000\000", 9) ||
            LE(ehdr->e_machine) != EM_VIDEOCORE3 ||
            LE(ehdr->e_type) != ET_EXEC ||
            !ehdr->e_shoff ||
            !ehdr->e_phoff ||
            LE(ehdr->e_shentsize) != sizeof(Elf32_Shdr) ||
            LE(ehdr->e_phentsize) != sizeof(Elf32_Phdr)) {
        fprintf(stderr, "%s: Invalid file format\n", filename);
        goto out;
    }
    const Elf32_Phdr* phdr = (const Elf32_Phdr*)(elf + LE(ehdr->e_phoff));
    if (LE(ehdr->e_phnum) != 1 || LE(phdr->p_type) != PT_LOAD) {
        fprintf(stderr, "%s: Expected a single load program header (link with -q -N)\n", filename);
        goto out;
    }
    if (LE(ehdr->e_entry) & 3) {
        // It seems like it's not possible to start executing from a function that's not 4-byte aligned??
        fprintf(stderr, "%s: Entry point is not 4-byte aligned\n", filename);
        goto out;
    }

	ret = vc4_mem_alloc(vc_mem, LE(phdr->p_memsz));
	if (ret)
		goto out;
	ret = -1;

	memcpy(vc_mem->hostptr, elf + LE(phdr->p_offset), LE(phdr->p_filesz));
	memset(vc_mem->hostptr + LE(phdr->p_filesz), 0, LE(phdr->p_memsz) - LE(phdr->p_filesz));

	int relocs_found = 0;

	const Elf32_Shdr* shdr = (const Elf32_Shdr*)(elf + LE(ehdr->e_shoff));
	for (unsigned i = 0; i < LE(ehdr->e_shnum); ++i) {
		const Elf32_Shdr* s = &shdr[i];
		if (LE(s->sh_type) == SHT_REL) {
			fprintf(stderr, "SH_REL not supported\n");
			goto out;
		} else if (LE(s->sh_type) != SHT_RELA) {
			continue;
		}

		relocs_found = 1;

		const Elf32_Rela* rel = (const Elf32_Rela*)(elf + LE(s->sh_offset));
		for (unsigned relnum = 0; relnum < LE(s->sh_size) / LE(s->sh_entsize); ++relnum, ++rel) {
			const int t =  ELF32_R_TYPE(LE(rel->r_info));
			const Elf32_Sym* sym = elf_symbol(ehdr, LE(s->sh_link), ELF32_R_SYM(LE(rel->r_info)));
			if (!sym) {
				fprintf(stderr, "Symbol not found\n");
				goto out;
			}
			uint32_t sym_addr = vc_mem->busaddr + LE(sym->st_value) + LE((uint32_t)rel->r_addend);
			int32_t relative = sym_addr - (vc_mem->busaddr + LE(rel->r_offset));
			uint8_t* target_addr = vc_mem->hostptr + LE(rel->r_offset);
			switch (t) {
			//case R_VC4_NONE:
			//case R_VC4_PCREL7_MUL2:
			//case R_VC4_PCREL8_MUL2:
			//case R_VC4_PCREL10_MUL2:
			//case R_VC4_PCREL16:
			case R_VC4_PCREL23_MUL2:
				reloc_ins32(target_addr, relative >> 1, 23);
				break;
			case R_VC4_PCREL27:
				reloc_masked_u32(target_addr + 2, relative, 27);
				break;
			case R_VC4_PCREL27_MUL2:
				// Weird encoding used for 32-bit bl
				relative >>= 1;
				target_addr[0] = (target_addr[0] & 0x80) | ((relative >> 16) & 0x7f);
				target_addr[1] = (target_addr[1] & 0xf0) | ((relative >> 23) & 0xf);
				write_u16le(target_addr + 2, (uint16_t)relative);
				break;
			//case R_VC4_PCREL32:
			//case R_VC4_IMM5_MUL4:
			//case R_VC4_IMM5_1:
			//case R_VC4_IMM5_2:
			//case R_VC4_IMM6:
			//case R_VC4_IMM6_MUL4:
			//case R_VC4_IMM11:
			//case R_VC4_IMM12:
			//case R_VC4_IMM16:
			//case R_VC4_IMM23:
			//case R_VC4_IMM27:
			case R_VC4_IMM32:
				write_u32le(target_addr + 2, sym_addr);
				break;
			//case R_VC4_IMM32_2:
			//case R_VC4_8:
			//case R_VC4_16:
			case R_VC4_32:
				write_u32le(target_addr, sym_addr);
				break;
			default:
                puts("");
                printf("Offset=%08X type=%s sym_addr=%X delta=%d\n", LE(rel->r_offset), reloc_name(t), sym_addr, relative);
                print_inst(target_addr);
				fprintf(stderr, "Unsupported relocation type %s\n", reloc_name(t));
				goto out;
			}
		}
	}

	if (!relocs_found) {
		// Of course it could be that there are no relocations, but much more likely an error
		fprintf(stderr, "No relocations found. (link with -q)\n");
		goto out;
	}

    *entry_point = vc_mem->busaddr + LE(ehdr->e_entry);

    ret = 0;
out:
    free(elf);
    return ret;
}

int main(void)
{
    int ret;
    ret = vc4_init();
    if (ret) {
        fprintf(stderr, "Could not init vc4\n");
        return -1;
    }
    vc4_mem code_mem = { 0 };
    vc4_mem data_mem = { 0 };
    uint32_t entry;
    ret = vc4_elf_load("code.elf", &code_mem, &entry);
    if (ret)
        goto out;
    ret = vc4_mem_alloc(&data_mem, 4096);
    if (ret)
		goto out;
    ret = vc4_run_vpu1(entry, data_mem.busaddr, 0, 0, 0, 0, 0);
	printf("Result: %d (0x%x)\n", ret, ret);
	for (int i = 0; i < 10; ++i)
		printf("[%d] = 0x%x\n", i, LE(((const uint32_t*)data_mem.hostptr)[i]));
out:
    vc4_mem_free(&data_mem);
    vc4_mem_free(&code_mem);
    vc4_free();
    return ret;
}
