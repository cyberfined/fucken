#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#define TEXT_ADDR (0x400000)
#define ENTRY_ADDR (TEXT_ADDR + 0xb0)
#define READ_OFFSET (6)

#define MOV_RSI_PATCH_OFFSET   (3)
#define CALL_RW_PATCH_OFFSET   (1)
#define NEAR_JMP_PATCH_OFFSET  (1)
#define SHORT_JMP_PATCH_OFFSET (1)
#define NEAR_JE_PATCH_OFFSET   (1)
#define SHORT_JE_PATCH_OFFSET  (2)

#define CELLS_COUNT 30000

#define ROUND_8(x) ((x + 7) & (-8))

static char mov_rsi[] = { 0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00 };
static char call_rw[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
static char near_jmp[] = { 0xeb, 0x00 };
static char short_jmp[] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };
static char near_je[] = { 0x74, 0x00 };
static char short_je[] = { 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00 };

static char rw_func[] = { 0x48, 0x31, 0xc0, 0xfe, 0xc0, 0xeb, 0x03, 0x48, 0x31, 0xc0, 0x48, 0x31, 0xd2, 0xfe, 0xc2, 0x48, 0x89, 0xc7, 0x0f, 0x05, 0xc3 };
static char inc_cell[] = { 0xfe, 0x06 };
static char dec_cell[] = { 0xfe, 0x0e };
static char next_cell[] = { 0x48, 0xff, 0xc6 };
static char prev_cell[] = { 0x48, 0xff, 0xce };
static char cmp_zero[] = { 0x80, 0x3e, 0x00 };
static char exit_code[] = { 0x48, 0x31, 0xc0, 0xb0, 0x3c, 0x48, 0x31, 0xff, 0x0f, 0x05 };

typedef struct {
    size_t   code_size;
    size_t   *jmp_lens, *indices;
    uint32_t cells_addr;
    bool     rw_usage;
} exe_info;

bool getExeInfo(const char *source, size_t size, exe_info *info) {
    size_t *jmp_lens, max_jmps = 8, cur_jmp = 0;
    size_t *indices = NULL, *file_offs = NULL, max_nesting = 2, cur_nesting = 0;
    size_t code_size = sizeof(mov_rsi) + sizeof(exit_code);
    bool rw_usage = false;

    jmp_lens = malloc(max_jmps * sizeof(size_t));
    if(!jmp_lens) {
        perror("getExeInfo");
        goto error;
    }

    indices  = malloc(max_nesting * sizeof(size_t));
    if(!jmp_lens) {
        perror("getExeInfo");
        goto error;
    }

    file_offs = malloc(max_nesting * sizeof(size_t));
    if(!file_offs) {
        perror("getExeInfo");
        goto error;
    }

    for(size_t i = 0; i < size; i++) {
        switch(*source++) {
            case '+':
                code_size += sizeof(inc_cell);
                break;
            case '-':
                code_size += sizeof(dec_cell);
                break;
            case '>':
                code_size += sizeof(next_cell);
                break;
            case '<':
                code_size += sizeof(prev_cell);
                break;
            case '.': case ',':
                rw_usage = true;
                code_size += sizeof(call_rw);
                break;
            case '[':
                if(cur_jmp == max_jmps) {
                    max_jmps *= 2;
                    jmp_lens = realloc(jmp_lens, max_jmps * sizeof(size_t));
                    if(!jmp_lens) {
                        perror("getExeInfo");
                        goto error;
                    }
                }

                if(cur_nesting == max_nesting) {
                    max_nesting *= 2;
                    indices = realloc(indices, max_nesting * sizeof(size_t));
                    if(!indices) {
                        perror("getExeInfo");
                        goto error;
                    }

                    file_offs = realloc(file_offs, max_nesting * sizeof(size_t));
                    if(!file_offs) {
                        perror("getExeInfo");
                        goto error;
                    }
                }

                code_size += sizeof(cmp_zero);
                jmp_lens[cur_jmp] = code_size;
                indices[cur_nesting] = cur_jmp;
                file_offs[cur_nesting] = i+1;

                cur_nesting++;
                cur_jmp++;
                break;
            case ']':
                if(cur_nesting == 0) {
                    fprintf(stderr, "Unexpected ] at %lu\n", i+1);
                    goto error;
                }
                cur_nesting--;

                size_t ind = indices[cur_nesting];
                jmp_lens[ind] = code_size - jmp_lens[ind];

                if(jmp_lens[ind] + sizeof(cmp_zero) + sizeof(near_jmp) <= 128)
                    code_size += sizeof(near_je) + sizeof(near_jmp);
                else
                    code_size += sizeof(short_je) + sizeof(short_jmp);
                break;
        }
    }

    if(cur_nesting != 0) {
        fprintf(stderr, "Expected ] for [ at %lu\n", file_offs[cur_nesting-1]);
        goto error;
    }

    if(rw_usage)
        code_size += sizeof(rw_func);

    info->code_size = code_size;
    info->jmp_lens = jmp_lens;
    info->cells_addr = TEXT_ADDR + ROUND_8(code_size) + 0x1000;
    info->indices = indices;
    info->rw_usage = rw_usage;

    free(file_offs);
    return true;
error:
    if(jmp_lens) free(jmp_lens);
    if(indices) free(indices);
    if(file_offs) free(file_offs);
    return false;
}

bool compile(int fd, exe_info *info, const char *source, size_t size) {
    size_t cur_nesting = 0, cur_jmp = 0;
    size_t code_size = sizeof(mov_rsi);
    int32_t jmp_len;
    bool w_stat = true;

    if(info->rw_usage) {
        if(write(fd, rw_func, sizeof(rw_func)) != sizeof(rw_func))
            goto error;
        code_size += sizeof(rw_func);
    }

    memcpy(mov_rsi + MOV_RSI_PATCH_OFFSET, &info->cells_addr, sizeof(info->cells_addr));
    if(write(fd, mov_rsi, sizeof(mov_rsi)) != sizeof(mov_rsi))
        goto error;

    for(size_t i = 0; i < size; i++) {
        char c = *source++;
        switch(c) {
            case '+':
                w_stat = write(fd, inc_cell, sizeof(inc_cell)) == sizeof(inc_cell);
                code_size += sizeof(inc_cell);
                break;
            case '-':
                w_stat = write(fd, dec_cell, sizeof(dec_cell)) == sizeof(dec_cell);
                code_size += sizeof(dec_cell);
                break;
            case '>':
                w_stat = write(fd, next_cell, sizeof(next_cell)) == sizeof(next_cell);
                code_size += sizeof(next_cell);
                break;
            case '<':
                w_stat = write(fd, prev_cell, sizeof(prev_cell)) == sizeof(prev_cell);
                code_size += sizeof(prev_cell);
                break;
            case '.': case ',':
                if(c == '.')
                    jmp_len = -(code_size+sizeof(call_rw));
                else
                    jmp_len = READ_OFFSET - code_size - sizeof(call_rw);
                memcpy(call_rw + CALL_RW_PATCH_OFFSET, &jmp_len, sizeof(jmp_len));
                w_stat = write(fd, call_rw, sizeof(call_rw)) == sizeof(call_rw);
                code_size += sizeof(short_jmp);
                break;
            case '[':
                w_stat = write(fd, cmp_zero, sizeof(cmp_zero)) == sizeof(cmp_zero);
                jmp_len = info->jmp_lens[cur_jmp];
                if(jmp_len + sizeof(near_jmp) < 128) {
                    jmp_len += sizeof(near_jmp);
                    memcpy(near_je + NEAR_JE_PATCH_OFFSET, &jmp_len, 1);
                    w_stat = w_stat && write(fd, near_je, sizeof(near_je)) == sizeof(near_je);
                    code_size += sizeof(cmp_zero) + sizeof(near_je);
                } else {
                    jmp_len += sizeof(short_jmp);
                    memcpy(short_je + SHORT_JE_PATCH_OFFSET, &jmp_len, sizeof(jmp_len));
                    w_stat = w_stat && write(fd, short_je, sizeof(short_je)) == sizeof(short_je);
                    code_size += sizeof(cmp_zero) + sizeof(short_je);
                }

                info->indices[cur_nesting] = cur_jmp;
                cur_nesting++;
                cur_jmp++;
                break;
            case ']':
                cur_nesting--;

                jmp_len = info->jmp_lens[info->indices[cur_nesting]];

                if(jmp_len + sizeof(cmp_zero) + sizeof(near_je) + sizeof(near_jmp) <= 128) {
                    jmp_len = 256 - jmp_len - sizeof(cmp_zero) - sizeof(near_je) - sizeof(near_jmp);
                    memcpy(near_jmp + NEAR_JMP_PATCH_OFFSET, &jmp_len, 1);
                    w_stat = write(fd, near_jmp, sizeof(near_jmp)) == sizeof(near_jmp);
                    code_size += sizeof(near_jmp);
                } else {
                    jmp_len = -(jmp_len + sizeof(cmp_zero) + sizeof(short_je) + sizeof(short_jmp));
                    memcpy(short_jmp + SHORT_JMP_PATCH_OFFSET, &jmp_len, sizeof(jmp_len));
                    w_stat = write(fd, short_jmp, sizeof(short_jmp)) == sizeof(short_jmp);
                    code_size += sizeof(short_jmp);
                }
                break;
        }

        if(!w_stat)
            goto error;
    }

    if(write(fd, exit_code, sizeof(exit_code)) != sizeof(exit_code))
        goto error;

    return true;
error:
    perror("compile");
    return false;
}

bool writeElfHeaders(int fd, exe_info *info) {
    Elf64_Ehdr ehdr;
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    ehdr.e_ident[EI_ABIVERSION] = 0;
    memset(ehdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD + 1);

    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 2;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;
   
    if(info->rw_usage)
        ehdr.e_entry = ENTRY_ADDR + sizeof(rw_func);
    else
        ehdr.e_entry = ENTRY_ADDR;

    Elf64_Phdr phdrs[2];
    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R | PF_X;
    phdrs[0].p_offset = 0;
    phdrs[0].p_vaddr = TEXT_ADDR;
    phdrs[0].p_paddr = TEXT_ADDR;
    phdrs[0].p_filesz = info->code_size;
    phdrs[0].p_memsz = info->code_size;
    phdrs[0].p_align = 0x1000;

    phdrs[1].p_type = PT_LOAD;
    phdrs[1].p_flags = PF_R | PF_W;
    phdrs[1].p_offset = ROUND_8(info->code_size);
    phdrs[1].p_vaddr = info->cells_addr;
    phdrs[1].p_paddr = info->cells_addr;
    phdrs[1].p_filesz = 0;
    phdrs[1].p_memsz = CELLS_COUNT;
    phdrs[1].p_align = 0x1000;
    
    if(write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
       write(fd, phdrs, sizeof(phdrs)) != sizeof(phdrs))
    {
        perror("writeElfHeaders");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    int fd = -1;
    char *source = MAP_FAILED;
    int res = 1;

    struct stat s_info;
    exe_info e_info;
    e_info.jmp_lens = NULL;
    e_info.indices = NULL;

    if(argc < 3) {
        fprintf(stderr, "Usage: %s <source> <output>\n"
                        "Brainfuck x86_64 compiler\n",
                        argv[0]);
        return 1;
    }

    fd = open(argv[1], O_RDONLY);
    if(fd < 0) {
        perror("open");
        goto error;
    }

    if(fstat(fd, &s_info) < 0) {
        perror("fstat");
        goto error;
    }

    source = (char*)mmap(NULL, s_info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(source == MAP_FAILED) {
        perror("mmap");
        goto error;
    }
    close(fd);

    fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0744);
    if(fd < 0) {
        perror("open");
        goto error;
    }

    if(!getExeInfo(source, s_info.st_size, &e_info))
        goto error;

    if(!writeElfHeaders(fd, &e_info))
        goto error;

    if(!compile(fd, &e_info, source, s_info.st_size))
        goto error;

    res = 0;
error:
    if(source != MAP_FAILED) munmap(source, s_info.st_size);
    if(fd > 0) close(fd);
    if(e_info.jmp_lens) free(e_info.jmp_lens);
    if(e_info.indices) free(e_info.indices);
    return res;
}
