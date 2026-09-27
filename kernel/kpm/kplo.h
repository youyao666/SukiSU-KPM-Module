/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPM_KPLO_H_
#define _KP_KPM_KPLO_H_

#include <uapi/linux/elf.h>

struct kpm_module;

int kpm_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct kpm_module *me);
int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                           struct kpm_module *me);

#endif
