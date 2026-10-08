# 从软件到芯片：Pavona 入门指南

*面向密码工程与后量子密码开发者 · 约 30 分钟阅读 · 2026 年 10 月 8 日*

如果你做过 ML-KEM、ML-DSA、SIMD 优化或密码软件实现，却还没有接触过芯片设计，Pavona 的文档可能会让人困惑：Ibex、ACC、KMAC、RTL、top-level、tapeout 同时出现，它们究竟处在系统的哪一层？这篇文章从最基础的概念开始，沿着一次密码运算的路径，把这些名字连接起来。读完后，你应该能看懂 Pavona 的架构图，并知道如何继续读它的代码和文档。

> **一句话理解：** Pavona 提供可组合的开放安全芯片模块及参考设计。主处理器运行固件，专门的密码协处理器执行部分密码运算，周围的硬件负责密钥、随机数、启动与安全隔离。

## 1. 先区分芯片、模块与参考设计

软件项目通常有库和应用程序。芯片项目也有类似的层次，但“把模块接起来”还涉及总线、时钟、复位、存储器和物理实现。

| 术语 | 可以先这样理解 | Pavona 中的例子 |
|---|---|---|
| **IP block** | 一个可复用的硬件模块 | ACC、KMAC、AES、随机数发生器、UART |
| **Top-level design** | 把多个模块连接成系统的设计 | Egret、Dragonfly |
| **Chip / silicon** | 经过制造、得到的物理芯片 | 完成 tapeout 后由代工厂制造的器件 |

IP（intellectual property）在这里不是一份“想法”，而是可集成的设计资产，通常包含 RTL、寄存器接口、文档、验证环境和集成信息。RTL 是描述数字电路行为的代码；它规定数据如何随时钟在寄存器和组合逻辑之间流动。[Pavona 的项目介绍](https://docs.pavona.org/)和[代码仓库](https://github.com/pavona/pavona)提供了这些模块的入口。

**Egret** 是独立的硬件信任根参考设计；**Dragonfly** 面向嵌入更大 SoC 的信任根。这里的信任根（Root of Trust，RoT）是系统中负责建立可信启动、身份和密钥保护等能力的基础部分。初次阅读时，不必先理解它们的每个外围设备；记住两者展示了不同的系统集成方式即可。[Pavona 安全概览](https://docs.pavona.org/book/doc/security/index.html)介绍了它们的角色。

## 2. 一张图看懂 Ibex、ACC 和 KMAC

```text
                    Pavona 系统
  ┌─────────────────────────────────────────┐
  │ Ibex：主处理器，运行固件                 │
  │     │                                   │
  │     ├── 调用密码库 cryptolib            │
  │     │        │                          │
  │     │        ├── ACC：执行专用密码程序  │
  │     │        └── KMAC：提供 SHA-3/SHAKE  │
  │     │                                   │
  │     └── 启动、外设与系统管理             │
  └─────────────────────────────────────────┘
```

**Ibex** 是主 CPU。你可以把它看成运行嵌入式固件的处理器。**ACC**（Asymmetric Cryptography Coprocessor）是独立的、可编程的密码协处理器，适合执行大整数和部分后量子密码运算。**KMAC** 是提供 SHA-3 / SHAKE 等功能的硬件模块。三者不是同一颗 CPU 的三个“线程”，而是系统内分工不同的硬件模块。[ACC 入门文档](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)给出了主处理器和 ACC 的交互图。

“协处理器”表示它替主处理器承担特定任务。Ibex 仍负责控制流程：准备输入、启动 ACC、等待完成、处理结果。ACC 在执行期间有自己的指令与数据存储器，并使用自己的寄存器和指令集。

## 3. 一次 ACC 运算是怎样发生的？

![Ibex、ACC 与 KMAC 的分工示意图](./diagrams/architecture.svg)

先不看任何汇编，观察一次调用的顺序：

1. Ibex 把 ACC 程序装入 ACC 的 **IMEM**（instruction memory）。
2. Ibex 把输入和常量放入 ACC 的 **DMEM**（data memory）。
3. Ibex 设置执行位，ACC 开始运行自己的程序。
4. ACC 完成运算并通知 Ibex。
5. Ibex 从 DMEM 读取输出。

```text
Ibex 固件 → 准备程序与输入 → ACC 独立执行 → 完成通知 → Ibex 读取结果
                         IMEM + DMEM
```

这有点像调用一个函数，但边界更明确：两边有不同的存储器、指令集和访问规则。例如，ACC 运行时 Ibex 不能读取它的存储器；ACC 遇到错误时可以进入锁定状态。[官方 ACC 介绍](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)说明了这些隔离规则。它们解释了为什么密码计算可以放在独立模块中，而不只是写成主 CPU 上的普通函数。

## 4. ACC 为什么有自己的指令集？

普通处理器擅长运行多种程序；密码运算则反复使用一些特殊操作。ACC 同时需要两类能力：

- **控制类操作：** 地址、加载存储、循环、分支等，使用 32 位通用寄存器（GPR）。
- **宽数据操作：** 大整数、模运算、向量运算等，使用 256 位宽寄存器（WDR）。

如果熟悉 AVX2，可以用“同样有 256 位寄存器”建立直觉，但两者的目标不同：AVX2 是通用 SIMD 扩展；ACC 的宽寄存器和指令围绕密码运算设计。

例如 `bn.mulqacc` 将 64 位的部分乘积累加到专用的 256 位累加器中，有利于实现 RSA、ECC 中的大整数乘法。`bn.addm` 和 `bn.subm` 则围绕模加、模减设计。这里的 `bn` 可以理解为 big number。[ACC ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)列出了精确语义；入门阶段先知道“为何需要这些指令”即可。

## 5. 为什么 PQC 又需要向量指令？

RSA 和 ECC 经常处理较大的整数。ML-KEM、ML-DSA 等基于格的方案则大量处理**多项式中的小系数**。以 ML-KEM 为例，计算会反复涉及数论变换（NTT）、系数乘法、模约减和数据重排。只把 256 位宽寄存器当作一个大整数，并不能高效表达这些操作。

因此，PQC 配置的 ACC 增加了向量指令：

| 指令 | 入门直觉 |
|---|---|
| `bn.addv` / `bn.subv` | 并行处理多个系数的加减 |
| `bn.shv` | 向量移位 |
| `bn.trn` | 向量转置或数据重排 |
| `bn.mulv` / `bn.mulv.l` | 向量乘法与累加 |

这些描述只是帮助建立直觉。实际优化必须查[ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)中的 lane 宽度、编码和运算语义，不能直接套用 AVX 指令的行为。PQC 配置还扩展了 ACC 的指令和数据存储空间，并增加与 KMAC 的直接连接；[ACC 工作原理文档](https://docs.pavona.org/book/hw/ip/acc/doc/theory_of_operation.html)解释了两种配置的差异。

## 6. KMAC 在这里做什么？

ML-KEM 和 ML-DSA 并不只有多项式算术。生成随机样本、扩展矩阵以及其他步骤需要 SHA-3 / SHAKE。ACC 负责适合它的算术部分，KMAC 硬件负责哈希与可扩展输出函数（XOF）相关工作。

PQC 配置让 ACC 与 KMAC 直接交换数据，避免每一步都绕经 Ibex 和系统存储器。于是一次后量子密码操作可能同时使用密码库、ACC 和 KMAC。它是“硬件与软件协同设计”的具体例子：运算放在哪里，会影响数据移动、性能和安全边界。[ACC 工作原理](https://docs.pavona.org/book/hw/ip/acc/doc/theory_of_operation.html)介绍了这条接口。

## 7. cryptolib 把这些模块连接起来

应用通常不会直接操作 ACC 寄存器，而是调用 **cryptolib** 提供的 API。以 ML-KEM 为例，可以先按下面的层次理解：

```text
应用 / 固件
    ↓
cryptolib API：密钥生成、封装、解封装
    ↓
实现与后端选择
    ├── 软件后端
    ├── ACC 后端
    └── 加固的 ACC 后端
             ↓
        ACC 运算 + KMAC
```

[Pavona cryptolib API 文档](https://docs.pavona.org/book/doc/security/cryptolib/cryptolib_api.html)列出了 ML-KEM-512/768/1024 的接口及这些后端。软件后端也会使用 KMAC 处理 Keccak 相关运算。后端选择说明：同一个上层 API 可以适配不同的硬件能力与安全要求。ML-DSA 也有对应的参数集和实现路径。

## 8. “安全实现”比正确输出多了什么？

普通功能测试首先关心：输出是否与标准或测试向量一致。安全芯片还要关心秘密在运算过程中的泄漏与残留：

- **侧信道：** 时间、功耗、电磁信号是否泄漏秘密？
- **故障注入：** 攻击者造成的计算或控制流错误会怎样？
- **状态清理：** 运算结束或出错后，寄存器和存储器里是否还留着敏感数据？
- **隔离：** 主处理器能在什么时刻访问协处理器的数据？

ACC 的设计包含无缓存、无分支预测、存储器扰码、硬件随机数访问、寄存器清理和错误锁定等机制。[ACC 安全特性](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)对这些机制有逐项说明。它们并不意味着任何运行在 ACC 上的程序都自动安全；具体算法仍需考虑实现方式和验证证据。

这也解释了为什么 cryptolib 区分普通 ACC 后端和**侧信道加固**的 ACC 后端。“加固”不只是“运行时间与秘密无关”，还可能涉及掩码等对物理泄漏的防护。[cryptolib 文档](https://docs.pavona.org/book/doc/security/cryptolib/cryptolib_api.html)说明了后端的差别。

## 9. simulation、FPGA、tapeout 有什么区别？

读硬件项目时，这三个词代表不同的验证与实现阶段：

| 阶段 | 做了什么 | 能说明什么 |
|---|---|---|
| **Simulation** | 在软件里运行 RTL 模型，例如使用 Verilator | 检查功能，方便调试 |
| **FPGA** | 把设计配置到可编程硬件板上 | 测试系统集成与固件行为 |
| **Tapeout** | 把完成物理设计的数据交给代工厂 | 进入实际芯片制造流程 |

仿真通过不等于真实芯片的时序、面积或功耗达标；FPGA 上的这些指标也不能直接等同于 ASIC。阅读性能结果时，先确认它来自哪一阶段。

## 10. 从哪里开始读代码？

带着前面的系统图，按调用链阅读比随机翻目录更有效：

1. 在 `sw/device/lib/crypto/include/` 找到一个熟悉的 API，例如 ML-KEM。
2. 在 `sw/device/lib/crypto/impl/` 观察实现和后端选择。
3. 在 `sw/acc/` 查找对应的 ACC 程序；先读 `code-snippets/` 中的小例子。
4. 对照 `hw/ip/acc/doc/` 的 [入门介绍](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)和 [ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)理解指令。
5. 最后再看 `hw/ip/acc/rtl/`，了解这些指令如何落到硬件模块。

此时最有用的问题是：输入从哪里来？哪个后端被选中？何时启动 ACC？哪些步骤使用 KMAC？结果如何回到调用者？只要能追清这条路径，Pavona 的密码软件栈就不再是一堆互不相关的缩写。

## 11. 没有开发板，如何开始？

**先用模拟器，不需要 FPGA 或实体芯片。** Pavona 提供 ACC 的 Python 指令集模拟器（ISS），可以在开发机上运行 ACC 程序。若想观察整个 SoC 中固件与外设的配合，再使用 Verilator 做 RTL 仿真。两者回答的问题不同：ISS 适合快速学习指令和调试小程序，Verilator 更接近硬件模块与系统级集成。[ACC 开发指南](https://docs.pavona.org/book/hw/ip/acc/doc/developing_acc.html)列出了这两种运行方式。

先按 [Pavona Getting Started](https://docs.pavona.org/book/doc/getting_started/) 配置依赖和工具链，再取得 [Pavona 仓库](https://github.com/pavona/pavona)。以下命令都在 **Pavona 仓库根目录** 执行，而不是个人网站目录。不同系统的前置依赖可能不同；先确认 `hw/ip/acc/util/acc_as.py` 能找到 RISC-V binutils 工具链。

```bash
# 下载仓库；依赖和工具链安装请按官方 Getting Started 操作
git clone https://github.com/pavona/pavona.git
cd pavona

# 先看看官方的小例子
ls sw/acc/code-snippets
```

`sw/acc/code-snippets/` 包含 `pseudo-ops.s`、`mul256.s`、`modexp.s` 等示例。第一次接触 ACC 汇编，先读 `pseudo-ops.s`；想理解大整数乘法，再看 `mul256.s`。[示例目录说明](https://docs.pavona.org/book/sw/acc/code-snippets/index.html)解释了各文件的用途。

## 12. 写第一个 ACC 程序：计算 7 + 5

下面的程序只使用 ACC 基础指令，把 DMEM 里的两个 32 位整数相加，再将结果写回 DMEM。先从这个例子理解“入口、加载、计算、存储、结束”，比直接读 ML-KEM 汇编容易得多。把它保存为 Pavona 仓库根目录下的 `hello_acc.s`：

```asm
.section .text.start
  jal x0, main          /* ACC 从这里开始，跳到 main */

.text
main:
  la   x2, input_a      /* x2 = input_a 的 DMEM 地址 */
  lw   x3, 0(x2)        /* x3 = 7 */
  la   x2, input_b
  lw   x4, 0(x2)        /* x4 = 5 */
  add  x5, x3, x4      /* x5 = 12 */
  la   x2, result
  sw   x5, 0(x2)        /* 把 12 写入 result */
  ecall                 /* 通知执行结束 */

.data
.balign 4
input_a: .word 7
input_b: .word 5
result:  .word 0
```

这里的 `la` 是装入地址的伪指令，`lw` / `sw` 分别从 DMEM 读取、写入一个 32 位字。`.text.start` 放程序入口；`.data` 放初始数据。[ACC 软件编写指南](https://docs.pavona.org/book/doc/contributing/sw/acc_sw.html)解释了段布局、汇编器和链接器。[ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)给出了 `lw`、`sw` 等指令的精确定义。

工具链配置好后，依次汇编、链接、在 Python ISS 中运行：

```bash
mkdir -p hello_acc_build
hw/ip/acc/util/acc_as.py -o hello_acc_build/hello_acc.o hello_acc.s
hw/ip/acc/util/acc_ld.py -o hello_acc_build/hello_acc.elf hello_acc_build/hello_acc.o
hw/ip/acc/dv/accsim/standalone.py --dump-dmem hello_acc_build/dmem.bin hello_acc_build/hello_acc.elf
xxd -g 4 -l 12 hello_acc_build/dmem.bin
```

查看输出中第三个 32 位字（`result`）：预期是十进制 **12**（十六进制 `0x0000000c`）。如果输出格式不易定位，可给模拟器加 `--verbose` 观察指令执行；具体参数以当前仓库的 `standalone.py --help` 为准。以上构建流程依据[官方 ACC 开发指南](https://docs.pavona.org/book/hw/ip/acc/doc/developing_acc.html)；首次下载完整工具链可能需要一些时间。

## 13. 下一步：从普通加法走向密码指令

理解上面的程序后，可以对比下面的**指令片段**。它使用宽寄存器 `w1` 和模数寄存器 `MOD` 做模加，不是一份可独立运行的程序：在执行前必须先装入输入和 `MOD`。

```asm
/* 假设 w1 已装入 b，MOD 已设为 m */
loopi 5, 1
  bn.addm w1, w1, w1   /* 每次执行 w1 = (2 × w1) mod m */
```

五次循环得到 `b × 2^5 mod m`。这个[官方 ACC 入门示例](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)展示了两件事：`loopi` 把固定次数的循环写进指令，`bn.addm` 把模加变成一条专用操作。此时再去看 `sw/acc/code-snippets/mul256.s`，就能循序理解宽寄存器和 `bn.mulqacc`。学习 PQC 向量指令时，再对照 `bn.addv`、`bn.trn`、`bn.mulv` 的 [ISA 语义](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)。

## 14. 把第一个程序拆开看：地址、寄存器和输出

第一个程序虽然只做一次加法，但已经包含了之后阅读所有 ACC 程序都会遇到的三种“位置”：**程序所在的 IMEM、数据所在的 DMEM，以及运算中的寄存器**。`.text.start` 和 `.text` 会被链接进 IMEM；`.data` 会被链接进 DMEM。这是 Harvard 架构的一种体现：指令地址和数据地址属于不同的空间。它们都可以从地址 0 开始，并不冲突。[ACC 软件编写指南](https://docs.pavona.org/book/doc/contributing/sw/acc_sw.html)解释了链接脚本的布局。

再看核心五行：

```asm
la  x2, input_a    /* x2 保存地址，不是输入值 */
lw  x3, 0(x2)      /* 从该地址读 4 字节到 x3 */
la  x2, input_b
lw  x4, 0(x2)
add x5, x3, x4    /* x5 = x3 + x4 */
```

`x2`、`x3`、`x4`、`x5` 都是 32 位 GPR。`la` 将标签解析成地址；`lw` 把地址中的一个 32 位字读进寄存器；`add` 只计算，不自动写回内存。因此后面的 `sw x5, 0(x2)` 必不可少。你可以试着删掉 `sw` 再运行：指令轨迹中可能仍能看到 `x5 = 12`，但 DMEM 中的 `result` 仍是初始化的 0。这是理解“寄存器中的结果”和“调用方可读到的结果”区别的最直接实验。

把第一个程序改成 `input_a = 0xffffffff`、`input_b = 1`，还会观察到一个重要现象：32 位 `add` 的结果是 `0x00000000`，高出的进位不会自动存到第二个寄存器。真实的大整数运算需要显式处理进位，或者使用 ACC 为宽数据设计的指令。这个小实验解释了为什么密码协处理器不能只依赖普通 32 位加法。

调试时，建议按“程序有没有到达 `ecall` → 内存地址有没有对齐 → 寄存器值对不对 → 输出是否写回 DMEM”的顺序排查。`lw` / `sw` 要求 4 字节对齐；后面将用到的 256 位宽加载和存储则要求 **32 字节对齐**。不同宽度的访问混用时，这是初学者容易遇到的错误。[ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)列出了相应错误条件。

## 15. 第二个完整程序：一次 256 位模加

![bn.addm 将 13 加 9 后按模数 17 得到 5](./diagrams/modular-add.svg)

现在写一个真正使用 ACC 宽寄存器的例子：计算 `(13 + 9) mod 17 = 5`。虽然这几个值很小，我们故意把每个值放进一个 256 位的数据槽，以学习 WDR、模数寄存器和宽数据读写。保存为 Pavona 仓库根目录下的 `mod_add.s`：

```asm
.section .text.start
  jal x0, main

.text
main:
  li      x3, 10       /* x3 指定目标宽寄存器 w10 */
  la      x2, a
  bn.lid  x3, 0(x2)   /* DMEM[a] → w10 */

  li      x3, 11
  la      x2, b
  bn.lid  x3, 0(x2)   /* DMEM[b] → w11 */

  li      x3, 12
  la      x2, modulus
  bn.lid  x3, 0(x2)   /* DMEM[modulus] → w12 */
  bn.wsrw 0, w12      /* w12 → MOD 特殊寄存器 */

  bn.addm w13, w10, w11  /* w13 = (13 + 9) mod 17 = 5 */

  li      x3, 13
  la      x2, result
  bn.sid  x3, 0(x2)   /* w13 → DMEM[result] */
  ecall

.data
.balign 32
/* 每个槽占 32 字节；低位 4 字节存放示例值 */
a:       .word 13
         .zero 28
b:       .word 9
         .zero 28
modulus: .word 17
         .zero 28
result:  .zero 32
```

注意 `bn.lid x3, 0(x2)` 的两个寄存器承担**不同角色**：`x2` 保存 DMEM 地址，`x3` 里面的数值 10 指向宽寄存器 `w10`。这里写的是 `x3`，不是直接写 `w10`，因为 `bn.lid` 采用间接指定宽寄存器的语法。`bn.sid` 反过来，把由 `x3` 指定的宽寄存器写到 `x2` 指定的地址。[`bn.lid` 与 `bn.sid` 的 ISA 定义](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)也规定了地址必须按 256 位（32 字节）对齐。

`bn.wsrw 0, w12` 把 `w12` 写入编号为 0 的宽特殊寄存器 **MOD**。下一行的 `bn.addm` 才能用它做模加。`bn.addm` 的重要前提是两个输入都小于模数；在这里 13 和 9 都小于 17，和为 22，减去一次 17 得 5。它不是会对任意巨大输入反复约减的“万能取模”指令。把输入改为 30 和 9 而不先约减，就不能按普通数学意义期待它返回 5。[`bn.addm` 的定义](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)明确说明了输入范围要求。

构建和运行的方法与第一个程序相同：

```bash
hw/ip/acc/util/acc_as.py -o hello_acc_build/mod_add.o mod_add.s
hw/ip/acc/util/acc_ld.py -o hello_acc_build/mod_add.elf hello_acc_build/mod_add.o
hw/ip/acc/dv/accsim/standalone.py --dump-dmem hello_acc_build/mod_add.bin hello_acc_build/mod_add.elf
xxd -g 4 -s 96 -l 32 hello_acc_build/mod_add.bin
```

由于四个 32 字节槽依次排列，`result` 从偏移 96 开始。预期第一个 32 位字是 `05000000`（小端字节顺序，对应数值 5），后面为 0。`xxd` 的显示方式是字节转储，不要把 `05000000` 误读成十六进制整数 `0x05000000`。如果想看每条指令，可对模拟器加 `--verbose`；若想看反汇编，可运行 `hw/ip/acc/util/acc_objdump.py -d hello_acc_build/mod_add.elf`。

## 16. 从一个 256 位整数到一组 PQC 系数

上一个程序把 `w10` 当成一个 256 位整数。但同样的 256 位，也能看成 **8 个 32 位系数**，或者 **16 个 16 位系数**。这就是向量指令的起点：不改变寄存器的总宽度，改变对寄存器内容的解释方式。

```text
同一个 256-bit WDR

标量视角： [              一个 256-bit 整数              ]
.8s 视角：[32][32][32][32][32][32][32][32]
.16h视角：[16][16][16][16] ... 共 16 个
```

例如，假设 `w10` 和 `w11` 各装有 8 个 32 位系数，可以写出下面的**指令片段**：

```asm
bn.addv.8s w12, w10, w11   /* 8 对 32 位 lane 分别相加 */
```

假如前两对 lane 分别是 `(1, 2)` 与 `(3, 4)`，相应输出就是 `3` 与 `7`。`.8s` 表示 8 个 32 位元素；`.16h` 表示 16 个 16 位元素。普通 `.8s` 形式只是按 lane 相加并截断到 32 位，**不会自动做 ML-KEM 模数约减**。ISA 还定义了启用模约减的 `m` 变体，使用前必须正确设置 MOD，并满足其输入范围要求。[`bn.addv` 的语义](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)对此有详细说明。

向量计算的难点不仅是一次算多少系数，还包括**系数放在哪些 lane**。NTT 的蝴蝶运算需要在不同阶段让特定系数两两相遇：算术指令负责加减和乘法，`bn.trn` 等指令负责重排。直观地说，如果两个需要相加的系数尚未进入对应的 lane，再快的加法指令也无用。阅读 ML-KEM 汇编时，可以在纸上给每个 lane 标上系数索引，追踪一次加载、一次重排和一次加法；这通常比先研究整套 NTT 更容易。

## 17. 学习代码时常见的四个问题

![bn.addv 对 8 个 32 位 lane 分别执行加法](./diagrams/vector-add.svg)

**为什么模拟器输出不是预期值？** 先确认 `.data` 的对齐和输出偏移，再确认程序是否执行到了 `sw` / `bn.sid`。模运算还要检查 MOD 是否初始化，以及输入是否在允许范围内。程序只在寄存器里算对、却没有把结果写回 DMEM，是常见原因。

**为什么 `bn.lid` 要通过一个 GPR 指定 WDR？** 这是它的指令格式。`li x3, 10` 后，`bn.lid x3, 0(x2)` 的目标是 `w10`；如果把 `x3` 改成 11，目标就变成 `w11`。也可以使用地址或寄存器索引的自增形式，但第一份程序先用最清楚的写法。[ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)列出了这些选项。

**Python ISS 与 Verilator 有什么区别？** ISS 是执行 ACC 指令语义的模型，适合快速运行小程序和看指令轨迹；Verilator 则模拟 RTL，能检查硬件实现与更完整的交互，但运行成本更高。先在 ISS 中把小程序写对，再按 [ACC 开发指南](https://docs.pavona.org/book/hw/ip/acc/doc/developing_acc.html)切换到 RTL 仿真，是自然的路径。

**为什么没有直接写 C？** ACC 面向密码卸载，目前没有普通 C 编译器。主处理器上的固件与 cryptolib 主要使用 C；ACC 程序主要使用汇编。它们通过 DMEM 和控制接口协作，不要把 Ibex 上的 C 程序和 ACC 内部程序混为一谈。[ACC 软件指南](https://docs.pavona.org/book/doc/contributing/sw/acc_sw.html)解释了当前工具链。

## 18. 用一组数字理解向量重排

前面说 `bn.trn` 会“重排数据”，这个词太抽象。可以用两个 8-lane 向量看它到底做了什么。假设每个 lane 为 32 位，从低位到高位分别为：

```text
w10 = [a0, a1, a2, a3, a4, a5, a6, a7]
w11 = [b0, b1, b2, b3, b4, b5, b6, b7]
```

`bn.trn1.8s` 取两个源向量中**偶数索引**的 lane，交错写入目标；`bn.trn2.8s` 取**奇数索引**的 lane：

```asm
bn.trn1.8s w12, w10, w11
bn.trn2.8s w13, w10, w11
```

```text
w12 = [a0, b0, a2, b2, a4, b4, a6, b6]
w13 = [a1, b1, a3, b3, a5, b5, a7, b7]
```

这两条只是**示意片段**，需要先把输入装入 `w10` 和 `w11`，并在支持 PQC 扩展的 ACC 配置下执行。注意 `trn1` 和 `trn2` 都不做加法或乘法；它们只改变 lane 的排列。把它们放在 `bn.addv` 前面，就能改变哪些系数相加。类似操作在 NTT 各阶段很常见，因为蝶形运算的配对关系会变化。[`bn.trn` ISA 文档](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)还给出了 16、64、128 位元素宽度的变体。

请不要把“向量相加”理解为一条指令就完成 NTT。实际内核还要解决 twiddle factor 的装载、乘法结果的约减、阶段间的系数布局、DMEM 访问与寄存器数量限制。上述例子只是让你在阅读汇编时能回答第一个关键问题：**一条指令之后，每个 lane 里到底是谁？**

## 19. ACC 程序如何接入真正的应用？

![bn.trn1 与 bn.trn2 交错重排向量 lane](./diagrams/transpose.svg)

前两个示例由 ISS 直接加载 ELF 并运行，所以我们没有写 Ibex 端的代码。实际系统中，主处理器侧还要负责把 ACC 程序和数据放到对应存储器、设置执行位、等待完成、检查状态、读取结果。下面是**概念性伪代码**，帮助你连接两个世界；函数名并非 Pavona 的可直接编译 API：

```c
// 概念示意：真实项目请使用 cryptolib / ACC driver 的接口
acc_load_program(program_image);  // 写入 ACC IMEM
acc_write_data(input, input_size); // 写入 ACC DMEM
acc_start();                       // 设置执行位
acc_wait_done();                   // 等待完成中断或轮询状态
if (acc_has_error()) {
    handle_error();
} else {
    acc_read_data(output, output_size);
}
```

为什么不在 `acc_start()` 之后立刻读回？因为 ACC 运行期间，Ibex 对其存储器的访问受到限制；程序需要执行 `ecall` 才会进入完成流程。完成后还要检查是否出现错误或锁定，不能仅凭“等了一段时间”就相信输出有效。[ACC 程序员指南](https://docs.pavona.org/book/hw/ip/acc/doc/programmers_guide.html)描述了状态轮询、完成中断、数据窗口和 `ecall` 的作用。

对于 ML-KEM，应用通常甚至看不到上面的加载与等待步骤。它调用 cryptolib 的密钥生成、封装或解封装 API；cryptolib 再根据构建配置选软件或 ACC 后端。ACC 算术程序与 KMAC 的 SHAKE 运算分别承担其中的工作。比较“ISS 里独立运行的小程序”和“cryptolib 里的完整算法”时，注意三层：**API 是调用者看到的承诺；后端决定使用哪种实现；硬件驱动负责把具体程序交给 ACC。** 这也解释了为什么分析性能不能只计算 ACC 核心的指令数，还要考虑程序加载、数据搬运和 KMAC 交互。

如果继续阅读源码，一个实用的方法是在每层只追一个输入和一个输出：密钥生成的输入随机性在哪里产生、如何传给后端、哪个 ACC 程序读取它、输出写到 DMEM 哪里、最后如何变成 API 返回的密钥。先追通一条完整路径，再去比较不同后端和加固方案，会比同时打开几十个文件容易得多。

## 20. 小结与术语速查

```text
Pavona：可组合的开放安全芯片项目
Ibex：运行固件的主处理器
ACC：运行专用密码程序的协处理器
KMAC：提供 SHA-3 / SHAKE 等功能的硬件模块
cryptolib：应用调用的密码软件接口与实现
IMEM / DMEM：ACC 的指令 / 数据存储器
GPR / WDR：ACC 的普通 / 256 位宽寄存器
RTL：描述数字硬件行为的代码
Top-level：连接多个 IP 模块的系统设计
Tapeout：把物理设计交给代工厂的阶段
```

把这些概念连起来，就得到阅读 Pavona 最重要的一条线：**应用调用 cryptolib，固件在 Ibex 上组织运算，ACC 与 KMAC 分担密码计算，底层 RTL 定义硬件行为，top-level 把模块组合成系统。**

### 延伸阅读

- [Pavona 文档首页](https://docs.pavona.org/)与 [GitHub 仓库](https://github.com/pavona/pavona)
- [ACC 入门介绍](https://docs.pavona.org/book/hw/ip/acc/doc/acc_intro.html)
- [ACC ISA 指南](https://docs.pavona.org/book/hw/ip/acc/doc/isa.html)
- [ACC 工作原理](https://docs.pavona.org/book/hw/ip/acc/doc/theory_of_operation.html)
- [cryptolib API](https://docs.pavona.org/book/doc/security/cryptolib/cryptolib_api.html)
