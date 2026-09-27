# SukiSU KPM Module

**insmod 一次，就有的 KPM——把 KernelPatch Module 机制完整移植进 SukiSU 可加载内核模块。**

无需解锁 BootLoader、无需刷写内核镜像：任何已获得 root（永久或临时）的 arm64 Android 设备，装载本模块后即获得完整的 KPM（KernelPatch Module）支持，SukiSU Ultra 管理器 KPM 页面与 `ksud kpm` 命令行均可正常使用。

## 这是什么

SukiSU-Ultra 的 KPM 特性在官方开源树中只有一层 **stub 空壳**（`kernel/kpm/kpm.c` 的 7 个 `sukisu_kpm_*` 桩函数）：真正的 ELF 加载器位于另一个仓库 [SukiSU_KernelPatch_patch](https://github.com/SukiSU-Ultra/SukiSU_KernelPatch_patch)（KernelPatch fork），官方机制是**用 KP 补丁把真实现 hook 进内核运行时替换桩**——意味着官方路线必须刷内核。

本项目把 KernelPatch 的真实加载器（`module.c` + `relo.c`，约 30KB）**移植进 kernelsu.ko 模块本体**，桩直接改为调用真实现。已在中途攻破并解决的技术关卡：

| # | 关卡 | 解法 |
|---|------|------|
| 1 | kpm/ 编译单元从未链入模块 | `kernelsu-objs` 显式追加 |
| 2 | LTO 残留 UND 符号 → 跳板死循环 | 修复链接后不再需要二进制手术 |
| 3 | 管理器 KPM 页即崩 | 链表初始化幂等挂载全部入口 |
| 4 | DDK 与设备内核 CFI 类型哈希跨 clang 版本不兼容 | inline-asm `blr` 远程调用器（编译器不可见，绝不插 CFI 检查） |
| 5 | `module_alloc` 裸内存 NX（取指即崩） | kallsyms 解析 `set_memory_x` 自补执行位 |
| 6 | 内核符号解析到别名/thunk 内部错位地址 | `.cfi_jt` 跳板优先 |
| 7 | **KP 符号模型**：kpm 代码把内核符号声明为指针变量（`extern void (*printk)(...)`），机器码 `adrp+ldr+blr` 要求符号值是"装着真地址的槽" | 加载器为每个 UND 符号分配 8 字节指针槽 |
| 8 | 指针槽放 kmalloc 区距模块内存 ~90TB，ADRP ±4GB 溢出 | 槽雕刻在模块镜像尾部（同区必然可达） |

## 使用

前置：arm64 设备、内核 `android12-5.10` GKI（其他 KMI 自行编译）、已 root、SukiSU Ultra **v4.2.0** 管理器（严格校验版本 40900 / uapi 2）。

```bash
# 已有 root shell（uid=0）的前提下：
setenforce 0
echo 0 > /proc/sys/kernel/modules_disabled   # MIUI 需要这步
ksud insmod kernelsu_kpm.ko allow_shell=1    # 或任意 kallsyms 加载器
setenforce 1
```

装载成功后（`lsmod | grep kernelsu` 可见），KPM ioctl 通道（`0xC0004BC8`）即完全可用——管理器 KPM 页面、或直接 ioctl 装载 `.kpm` 模块：

```
kpm: calling init at ...
kpm hello init, event: load-file, args: FINAL
kpm: [kpm-hello-demo] succeed with [FINAL]
```

## 构建

fork 本仓库后 GitHub Actions 自动可用（push 或手动触发）：

- 容器：`ghcr.io/ylarod/ddk-min:<KMI>-<date>`（默认 `android12-5.10-20260828`）
- 环境包含 DDK modpost 阉割破解（还原 `check_exports` / CRC 生成 + `KBUILD_MODPOST_WARN=1`），否则模块 `__versions` 段为空、MODVERSIONS 内核一律拒载
- 换 KMI：改 workflow 中容器 tag 与 kernel 源码版本

## 实测

- Redmi Note11TPro（MTK 天玑 8100，MIUI，GKI `5.10.226-android12`，CFI+SCS+PAC 全开，未解 BL）
- SukiSU Ultra v4.2.0 管理器（40900 / uapi 2 / v4.2.0-release）三重校验全绿
- hello.kpm 装载 → init 执行 → 模块表在册（num=1）全链路通过

## 致谢与许可

- **[酷安 @御坂114515号](https://www.coolapk.com)（CVE-2026-43499 exploit 作者）** —— 免解锁 BL 的临时 root 能力是本路线的地基：没有这个提权通道，"不刷内核装载模块"就无从谈起
- **红米 Note11TPro 免 BL 临时 root 教程的分享者与社区** —— MIUI IMQS 装载通道等关键拼图来自社区教程
- [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) 及其贡献者
- [KernelPatch](https://github.com/bmax121/KernelPatch) / bmax121（`module.c` / `relo.c` / `kpmodule.h` 移植母本）

本项目为 GPL-2.0-or-later（与上游一致）。内核模块开发有风险，装载失败可能需要重启；请在你能承受的设备上使用。
