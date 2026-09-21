# KDASICS：内核不可信代码的 CSR 写保护与驱动隔离

日期：2026-09-21。

## 结论

禁止 **S 态不可信代码直接发出 CSR 写请求** 是合理的隔离默认策略。需要保护的既包括 `satp/stvec/sepc/sscratch/sstatus/sie` 等系统状态，也包括 S 态可写的 DASICS 边界、配置和返回地址 CSR。按 CSR 指令统一拦截，比维护敏感寄存器黑名单更能覆盖别名和扩展。

但“驱动无需 CSR”不成立：平台定时器、中断控制器直接读写 CPU CSR；普通驱动会通过关中断、带 IRQ 保护的锁、用户内存访问等接口产生 CSR 操作。适合的设计是 **不可信域禁止直接写，必要操作通过受控的可信入口执行**。不宜开放任意 `write_csr(number, value)` 代理。

本次只修改 QEMU 的显式 CSR 写请求授权及回归测试，没有修改 Linux 驱动和异常恢复逻辑。该补丁并不等同于完整的驱动隔离实现。

## 检查的源码与构建

- QEMU：`qemu-dasics`，基于 `8c1345e7b5`（VERSION 为 8.1.50），从 `dasics-master-8.1.0` 创建并切换到 `kdasics`。
- Linux：相邻 `linux` 仓库的 `dasics-smode` 分支，`503b5c678b41`，5.10.167；保留已有 defconfig 修改和构建产物。本报告描述本地版本，不能直接当作其他内核版本的结论。
- 原有 QEMU `build/`、`build-smolagents/` 含指向其他目录的构建路径，另建 `build-kdasics/`，避免混用。
- 工作区 `run_qemu.sh` 默认仍指向 `/data/lgf/dasics` 下的旧 QEMU，且依赖未在当前目录发现的 overlay DTB；不能用该默认入口证明新补丁已运行。新二进制为 `qemu-dasics/build-kdasics/qemu-system-riscv64`。

## QEMU 改动与语义

旧的 `target/riscv/csr.c:riscv_csrrw_check()` 只对 U 态不可信代码访问部分 DASICS CSR 增加检查，没有 S 态全局写限制。H 扩展开启时 HS 的 CSR 有效特权还会加一，因此不能用 `effective_priv == PRV_S` 判定内核态。

新增 `helper_dasics_csr_write_check()`，在四个写操作翻译入口 `do_csrw/do_csrrw/do_csrw_i128/do_csrrw_i128` 调用，覆盖六种 CSR 指令及丢弃返回值的形式。条件为：

1. CPU 的 DASICS 功能开启；
2. 实际执行特权为 S，包括 HS/VS；
3. `MCFG_SENA` 开启；
4. 当前指令 PC 按现有 `dasics_in_trusted_zone()` 判断位于不可信区。

满足时，在任何 CSR accessor 或目标通用寄存器写回前抛出 **illegal instruction，cause=2**。异常入口自身按架构更新的 trap CSR 不受此限制。代码传入实际指令 PC，并支持翻译块的相对 PC 模式，不依赖可能滞后的 `env->pc`。

| 指令形式 | 新增策略 |
| --- | --- |
| CSRRW / CSRRWI，包括 rd=x0、rs1=x0、立即数 0 | 属于写请求，拒绝 |
| CSRRS / CSRRC，rs1 不是 x0 | 属于写请求，拒绝；即使该寄存器的值为 0 |
| CSRRSI / CSRRCI，立即数非 0 | 属于写请求，拒绝 |
| CSRRS / CSRRC，rs1=x0 | 保持原有读取权限检查 |
| CSRRSI / CSRRCI，立即数 0 | 保持原有读取权限检查 |

这个区分符合 [RISC-V Zicsr 规范](https://docs.riscv.org/reference/isa/unpriv/zicsr.html)。仅在 `riscv_csrrw_check()` 检查 `write_mask != 0` 会漏掉“非 x0 寄存器持有零值”的写请求。现有译码器已经区分纯读与写请求，因此选择在写入口检查，而不是改变 CSR API 对调试器、内部调用及读取的语义。

可信 S 态、M 态、SENA 关闭时以及原有 U 态访问策略保持原行为；标准特权、CSR 是否存在、只读 CSR 等检查仍执行。此补丁不会赋予 S 态写 M 级 CSR 的能力。例如 `dsmcfg=0xbc0`、`dsmbound*=0xbc2/0xbc3` 原本就是 M 级，不能把它们误报成以前允许 S 态直接关闭 SENA 的路径。

边界行为继承现有实现：主区上下界均包含；`lo > hi` 被视为该级 DASICS 未有效启用，所有该级代码被视为可信。本补丁没有改变这一配置语义，部署时必须由可信管理层建立有效边界。

## Linux 驱动的实际 CSR 需求

下列路径相对于相邻的 `linux/` 目录。

| 使用场景 | 本地源码证据 | 对隔离策略的影响 |
| --- | --- | --- |
| 每 hart 定时器 | `drivers/clocksource/timer-riscv.c:27,87` 对 `CSR_IE` set/clear；`arch/riscv/include/asm/timex.h:53` 的 `get_cycles()` 读取 `CSR_TIME` | S 模式写 sie.STIE，读 time，并调用 SBI 设置定时器。适合保留在可信平台层 |
| CPU 本地中断控制器 | `drivers/irqchip/irq-riscv-intc.c:52–70` | mask/unmask、CPU 上下线直接写 sie，相应操作应由可信 IRQ 层拥有 |
| 直接关/开中断 | `drivers/char/random.c:970–984` 调用 `local_irq_disable/enable()`；`arch/riscv/include/asm/irqflags.h:21–59` | 最终 set/clear sstatus.SIE。内联到被隔离代码中会被阻断 |
| 普通网卡的中断保护锁 | `drivers/net/ethernet/intel/e1000/e1000_main.c:3608` 及其他统计/发送路径调用 `spin_lock_irqsave()`；`include/linux/spinlock_api_smp.h:104–112` 执行 `local_irq_save()` | 存在 CSR 需求，但指令可能落在可信内核锁函数中，不能仅凭驱动调用锁就断言一定在驱动 PC 处被拒绝 |
| 用户内存读写 | `drivers/char/random.c:1325–1349` 的 get_user/put_user；`arch/riscv/include/asm/uaccess.h:24–27,181–195` | 宏/内联代码临时 set/clear sstatus.SUM，若位于不可信驱动会被拒绝。可由可信复制接口完成 |
| 较大的用户内存复制 | `arch/riscv/lib/uaccess.S:20,49,76,98` | 复制实现也会操作 SUM，通常在内核函数中执行；需要合法的可信调用入口和缓冲区校验 |
| 性能计数 | `arch/riscv/kernel/perf_event.c:188,191` | 本地实现读取 cycle/instret；当前写保护保留这类读取。不能据此假设所有版本 PMU 驱动都只读 CSR |

S 模式下 `CSR_STATUS/CSR_IE/SR_IE` 分别映射为 `sstatus/sie/SIE`，见 `arch/riscv/include/asm/csr.h:137–146`。其他架构驱动中同名的 `csr_read/csr_write`，以及设备的控制/状态寄存器，不应自动归为 RISC-V CPU CSR。

本地 `.config` 启用了 SMP，未开启 DEBUG_SPINLOCK、DEBUG_LOCK_ALLOC；未设置 INLINE_SPIN_LOCK_IRQSAVE。`kernel/locking/spinlock.c:157–161` 存在导出的 `_raw_spin_lock_irqsave()`。因此以当前配置看，e1000 的这条路径更可能在内核锁函数内执行 CSR 指令。应以实际隔离对象、编译配置和反汇编中的指令 PC 为最终依据；本次未重新编译并逐个运行驱动。

### 为什么禁止写合理

- 写 satp 可以影响地址翻译，写 stvec/sepc/sscratch 可以破坏异常入口和返回上下文，写 sstatus 可改变中断及用户页访问状态。
- 写 S 态可访问的 DASICS 配置/边界/返回 CSR，可以绕过组件原本获得的权限。
- fflags/frm/fcsr、向量 CSR 等虽未必都是隔离控制面，既然策略是全部显式 CSR 写禁止，也统一拒绝；需要这类操作的组件要通过受控服务或另行设计上下文支持。
- 写锁定不是读取锁定。读 time/cycle 对计时常见；如另有计时侧信道或信息暴露的威胁模型，应另行设计读策略，而不是为本次需求默认禁止所有读。

### 可落地的驱动边界

1. 优先隔离普通设备驱动的业务逻辑和协议处理；CPU 中断控制器、定时器、页表切换、异常处理保留可信。
2. 将 `irq_save/restore`、`get_user/put_user` 等可能内联 CSR 的操作改为可信入口。接口只允许限定语义，例如保存/恢复允许的中断位；不能接受任意 sstatus 值或任意 CSR 编号。
3. 可信入口校验锁对象、缓冲区、调用状态等；管理关中断的配对及故障回退，避免组件异常退出后中断长期关闭或锁未释放。
4. 核对所有导入函数通过 DASICS 合法 gate 调用。即使 CSR 指令在可信函数中能通过本补丁，也不意味着整个调用的参数和权限安全。
5. SBI、SRET、页表内存写、MMIO/DMA 是其他影响系统状态的路径。已有 `helper_sret()` 未加 DASICS 域检查；本次写保护不声称修复这些问题，也不禁止浮点/向量运算或 trap 自动更新 CSR 的隐式行为。

## Linux 异常处理的集成限制

本次使用 illegal instruction，沿用已有 DASICS CSR 拒绝的异常类型，没有新增 CSR fault ABI。`arch/riscv/kernel/traps.c:90–113` 将内核态非法指令交给 `do_trap_error()`，未被 exception fixup 接管时进入 `die()`，可导致 Oops/任务终止，某些上下文会 panic。

`do_trap_dasics()` 中已有的 compartment trap/unwind 路径（同文件约 191 行起）不会因为 cause=2 自动接管本次拒绝。因此，“硬件模拟器成功阻断”与“驱动隔离调用能安全恢复”是两件需要分别验证的事。后续应将确认来自隔离域的 CSR 违规接入受控终止/回退，或共同设计独立的 DASICS CSR fault 原因；不能在异常处理里盲目跳过违规指令。

## 验证与复现

构建：

```sh
mkdir -p build-kdasics
cd build-kdasics
../configure --target-list=riscv64-softmmu --disable-werror \
  --disable-docs --disable-download --disable-gtk --disable-sdl \
  --disable-vnc --disable-tools --disable-guest-agent
ninja -j 12 qemu-system-riscv64
```

测试文件为 `tests/tcg/riscv64/dasics-csr-write.S`，已接入 `Makefile.softmmu-target` 的 `run-dasics-csr-write` 和 `run-dasics-csr-write-no-h`。可在源码根目录独立复现：

```sh
riscv64-linux-gnu-gcc -march=rv64gcv -mabi=lp64d -fno-pie \
  -c tests/tcg/riscv64/dasics-csr-write.S -o build-kdasics/dasics-csr-write.o
riscv64-linux-gnu-ld -T tests/tcg/riscv64/semihost.ld \
  build-kdasics/dasics-csr-write.o -o build-kdasics/dasics-csr-write
timeout 20 build-kdasics/qemu-system-riscv64 -M virt \
  -cpu rv64,v=true,h=true -display none -serial none -monitor none \
  -bios none -semihosting -kernel build-kdasics/dasics-csr-write
# 再将 h=true 改为 h=false 运行
```

实际结果：

- 新 QEMU 构建成功；两条 Makefile 回归目标均退出 0。
- 19 个普通/S 级/DASICS/FP/向量 CSR，每个 14 种写形式，检查 cause、精确故障 PC、mtval、目标通用寄存器未写回、目标 CSR 值未变，并验证纯读形式。
- 开启 H 时另外覆盖 hstatus、hcounteren、hgatp、htimedelta，验证 HS 不会因 CSR 有效特权加一而漏检。
- 扫描全部 4096 个 CSR 编号的 CSRRW 写请求；包括原本就不存在或权限不足的编号，均要求拒绝。该扫描与可正常读取的代表 CSR 状态检查配合，不能单靠扫描证明各编号均由新策略拒绝。
- 验证可信 S 态、SENA 关闭、仅 SENA 开启时 U 态写 fcsr，以及从可信区顺序跨出/从外部顺序跨入的 PC 判断。
- 原有 `build-smolagents/qemu-system-riscv64` 运行同一基础测试退出 1：首个不可信 sstatus 写没有按要求触发非法指令，随后测试返回失败。该旧构建不是此次从基准提交重新编译，作为现存二进制的修复前对照记录。
- 新 QEMU 搭配现有 OpenSBI `fw_jump.elf` 和 Linux `arch/riscv/boot/Image` 启动到 `DASICS rootfs ready` 和 `/ #`。这是默认启动冒烟验证，没有加载隔离驱动 profile，不代表驱动隔离集成测试通过。
- RV32/RV128 写路径共用该翻译检查，已从源码覆盖；此次动态测试仅运行 RV64，未运行 VS guest、RV32/RV128 或全部驱动。
