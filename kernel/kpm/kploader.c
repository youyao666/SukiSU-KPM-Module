/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ported from KernelPatch kernel/patch/module/module.c (bmax121, GPL-2).
 * Real KPM ELF loader: layout -> alloc exec memory -> resolve symbols ->
 * apply relocations -> call .kpm.init.
 *
 * Environment adaptations for building inside the kernelsu.ko module:
 *   kp_malloc_exec/kp_free_exec  -> module_alloc / module_memfree
 *   symbol_lookup_name           -> sukisu_compact_find_symbol (kpm/compact.c)
 *   logk*                        -> pr_info/pr_err
 *   flush_icache_all             -> inline "ic ialluis" sequence
 *   file read (vfs_llseek)       -> filp_open + i_size + kernel_read loop
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <asm/elf.h>
#include <asm/cacheflush.h>
#include <uapi/linux/elf.h>
#include <uapi/linux/fs.h>

#include "kploader.h"
#include "kplo.h"
#include "compact.h"
#include "infra/symbol_resolver.h"

#define SZ_128M 0x08000000

#define align(X) ALIGN(X, PAGE_SIZE)

#ifndef ARCH_SHF_SMALL
#define ARCH_SHF_SMALL 0
#endif

#define logkd(fmt, ...) pr_info("kpm: " fmt, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err("kpm: " fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) pr_info("kpm: " fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) pr_err("kpm: " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) pr_info("kpm: " fmt, ##__VA_ARGS__)

static inline unsigned long symbol_lookup_name(const char *name)
{
    return sukisu_compact_find_symbol(name);
}

/*
 * module_alloc/module_memfree are not exported on arm64 5.10 (no CRC in
 * Module.symvers -> insmod would fail with unknown symbol), so resolve
 * them from kallsyms at runtime like the rest of the unexported symbols.
 */
static void *(*pfn_module_alloc)(unsigned long);
static void (*pfn_module_memfree)(void *);

static void kp_execmem_resolve(void)
{
    if (!pfn_module_alloc)
        pfn_module_alloc = (void *)find_kernel_symbol_exact("module_alloc");
    if (!pfn_module_memfree)
        pfn_module_memfree = (void *)find_kernel_symbol_exact("module_memfree");
}

static inline void *kp_malloc_exec(unsigned int size)
{
    kp_execmem_resolve();
    if (!pfn_module_alloc)
        return NULL;
    return pfn_module_alloc(size);
}

static inline void kp_free_exec(void *ptr)
{
    if (pfn_module_memfree && ptr)
        pfn_module_memfree(ptr);
}

static inline void kp_flush_icache_all(void)
{
    /* same sequence as arm64 flush_icache_all, no export dependency */
    __asm__ __volatile__("ic ialluis" ::: "memory");
    __asm__ __volatile__("dsb nsh" ::: "memory");
    __asm__ __volatile__("isb" ::: "memory");
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct kpm_module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct kpm_load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct kpm_load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct kpm_load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0) return i;
    }
    return 0;
}

static void *get_sh_base(struct kpm_load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static unsigned long get_sh_size(struct kpm_load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct kpm_module *mod, struct kpm_load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = align(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct kpm_module *mod, const struct kpm_load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;
    unsigned long addr = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                logkd("Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF:
            addr = symbol_lookup_name(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct kpm_module *mod, const struct kpm_load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = kpm_apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = kpm_apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
        if (rc < 0) break;
    }
    return rc;
}

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct kpm_module *mod, struct kpm_load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct kpm_load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct kpm_module *mod, struct kpm_load_info *info)
{
    logkd("alloc module size: %x\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        logkd("    %s %px %llx\n", sname, dest, shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct kpm_load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct kpm_load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr))
        return -ENOEXEC;
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff))
        return -ENOEXEC;
    return 0;
}

static struct kpm_module kpm_modules = { 0 };
static int kpm_loader_inited;
static spinlock_t kpm_module_lock;

void kpm_loader_init(void)
{
    if (kpm_loader_inited) return;
    INIT_LIST_HEAD(&kpm_modules.list);
    spin_lock_init(&kpm_module_lock);
    kpm_loader_inited = 1;
    logkd("loader init\n");
}

long kpm_load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct kpm_load_info load_info = { .len = len, .hdr = data };
    struct kpm_load_info *info = &load_info;
    long rc = 0;

    kpm_loader_init();

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    if (kpm_find_module(info->info.name)) {
        logkfd("%s exist\n", info->info.name);
        rc = -EEXIST;
        goto out;
    }

    struct kpm_module *mod = (struct kpm_module *)vmalloc(sizeof(struct kpm_module));
    if (!mod) return -ENOMEM;
    memset(mod, 0, sizeof(struct kpm_module));

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);

    if ((rc = move_module(mod, info))) goto free;
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) goto free;

    kp_flush_icache_all();

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        list_add_tail(&mod->list, &kpm_modules.list);
        goto out;
    } else {
        logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, (int)rc);
        (*mod->exit)(reserved);
    }

free:
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
out:
    return rc;
}

// todo: lock
long kpm_unload_module(const char *name, void *__user reserved)
{
    if (!name) return -EINVAL;
    logkfe("name: %s\n", name);

    rcu_read_lock();
    long rc = 0;

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    list_del(&mod->list);
    rc = (*mod->exit)(reserved);

    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);

    kp_free_exec(mod->start);
    kvfree(mod);

    logkfi("name: %s, rc: %d\n", name, (int)rc);

out:
    rcu_read_unlock();
    return rc;
}

long kpm_load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) return -EINVAL;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        goto out;
    }

    loff_t len = i_size_read(file_inode(filp));
    logkfd("module size: %llx\n", len);
    if (len <= 0 || len > SZ_128M) {
        rc = -EINVAL;
        goto close;
    }

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    while (pos < len) {
        ssize_t n = kernel_read(filp, (char *)data + pos, len - pos, &pos);
        if (n < 0) {
            logkfe("read module: %s error\n", path);
            rc = n;
            goto free;
        }
        if (n == 0) break;
    }

    if (pos != len) {
        logkfe("read module: %s short\n", path);
        rc = -EIO;
        goto free;
    }

    filp_close(filp, 0);
    filp = NULL;

    rc = kpm_load_module(data, len, args, "load-file", reserved);
free:
    if (filp) filp_close(filp, 0);
    kvfree(data);
    return rc;
close:
    filp_close(filp, 0);
out:
    return rc;
}

long kpm_module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);

    long rc = 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl0 || !*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto out;
    }

    if (mod->ctl_args) kvfree(mod->ctl_args);

    mod->ctl_args = vmalloc(args_len + 1);
    if (!mod->ctl_args) {
        rc = -ENOMEM;
        goto out;
    }

    strcpy(mod->ctl_args, ctl_args);

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    logkfi("name: %s, rc: %d\n", name, (int)rc);
out:
    rcu_read_unlock();
    return rc;
}

long kpm_module_control1(const char *name, void *a1, void *a2, void *a3)
{
    logkfi("name %s, a1: %px, a2: %px, a3: %px\n", name, a1, a2, a3);
    long rc = 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl1 || !*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    logkfi("name: %s, rc: %d\n", name, (int)rc);
out:
    rcu_read_unlock();
    return rc;
}

struct kpm_module *kpm_find_module(const char *name)
{
    struct kpm_module *pos;
    kpm_loader_init();
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return 0;
}

int kpm_get_module_nums(void)
{
    kpm_loader_init();
    rcu_read_lock();

    struct kpm_module *pos;
    int n = 0;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        n++;
    }
    rcu_read_unlock();

    logkfd("%d\n", n);
    return n;
}

int kpm_list_modules(char *out_names, int size)
{
    kpm_loader_init();
    rcu_read_lock();

    struct kpm_module *pos;
    int off = 0;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
    }
    if (off > 0) out_names[off - 1] = '\0';

    rcu_read_unlock();
    return off;
}

int kpm_get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) return -ENOENT;

    int sz = snprintf(out_info, size - 1,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args);

    if (sz > 0) out_info[sz - 1] = '\0';

    rcu_read_unlock();
    return sz;
}
