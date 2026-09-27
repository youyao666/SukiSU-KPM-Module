/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ported from KernelPatch kernel/patch/include/module.h (bmax121, GPL-2)
 * Types renamed to avoid colliding with the kernel's own struct module /
 * find_module / apply_relocate_add when built as a loadable module.
 */

#ifndef _KP_KPM_KPMODULE_PORT_H_
#define _KP_KPM_KPMODULE_PORT_H_

#include <linux/types.h>
#include "kpmodule.h"

struct kpm_load_info
{
    struct
    {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
    } info;
    const Elf64_Ehdr *hdr;
    unsigned long len;
    Elf64_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct
    {
        unsigned int sym, str, mod, info;
    } index;
};

struct kpm_module
{
    struct
    {
        const char *base, *name, *version, *license, *author, *description;
    } info;

    char *args, *ctl_args;

    mod_initcall_t *init;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_exitcall_t *exit;

    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;

    void *start;

    struct list_head list;
};

void kpm_loader_init(void);
long kpm_load_module(const void *data, int len, const char *args, const char *event, void *__user reserved);
long kpm_load_module_path(const char *path, const char *args, void *__user reserved);
long kpm_module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen);
long kpm_module_control1(const char *name, void *a1, void *a2, void *a3);
long kpm_unload_module(const char *name, void *__user reserved);
struct kpm_module *kpm_find_module(const char *name);

int kpm_get_module_nums(void);
int kpm_list_modules(char *out_names, int size);
int kpm_get_module_info(const char *name, char *out_info, int size);

#endif
