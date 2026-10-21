# 翻转一个比特：密码学感知测试在 PQC 实现里找到了什么

*面向密码工程师的论文笔记 · 约 35 分钟阅读 · 2026 年 10 月 21 日*

已知答案测试（Known-Answer Test，KAT）检查的是：实现在一组固定的、约一百个输入上，输出与参考实现相同。AddressSanitizer 等 sanitizer 检查的是：实现没有读写不属于自己的内存。这两项检查都发现不了下面这类问题：`Decaps`（密钥封装机制 KEM 的解封装函数）对一个本应拒绝的密文返回了原来的密钥；`Verify` 接受了一个尾部追加了多余字节的签名。这类 bug 不会让程序崩溃，但安全性质已经失效，而且没有任何报错。

本文介绍 Giacomo Fenzi、Jan Gilcher、Fernando Virdia 发表在 TCHES 2026 的一篇论文。论文把安全定义写成测试程序，性质被违反时程序会**主动崩溃**。我先介绍方法，再从实现者的角度看它的发现：哪里出了问题，原因是什么，自己代码里的哪项检查可以提前发现它。

> **一句话理解：** 取一个合法输入，翻转一个比特，检查输出在应当改变时改变、在不应改变时保持不变。把这件事写成一个通用测试程序，就能找到 IND-CCA 失效、强不可伪造失效、越界读，以及几类普通 fuzzing 发现不了的意外性质。

## 0. 导读

结论先行。先说明几个贯穿全文的术语：

- **Fuzzing（模糊测试）**：用大量自动生成的输入运行程序，记录崩溃。**[AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi)** 是常用的 fuzzer。
- **IND-CCA**：KEM 的标准安全定义。攻击者可以请求解封装除挑战密文以外的任何密文，但仍无法得到挑战密钥的任何信息。
- **sUF-CMA（强不可伪造）**：签名的安全定义。攻击者看过若干合法签名后，无法给出任何新的合法“消息–签名”对，包括对已签过的消息再给出另一个签名。
- **可塑性（malleability）**：本文中指改变了某个输入，输出却没有变化。

结论如下：

1. **对安全影响最大的 bug 不会崩溃。** LibOQS 是 Open Quantum Safe 项目维护的后量子密码 C 库。在 LibOQS 0.8.0 和 0.14.0 上，常规 AFL++ 测试没有发现任何问题；在同样的版本上，本文的测试分别找到 2 个和 25 个强不可伪造反例。所有版本合计，常规测试漏掉了 13 个 IND-CCA 反例和 36 个 sUF-CMA 反例。
2. **大部分真实发现都是“非规范编码”。** 如果不止一种字节串能解码为同一个值，这种编码就是非规范的。NTRU 不检查密文填充位；Falcon 接受“−0”和非零填充；SNOVA 接受尾部未用比特取任意值；CROSS 忽略签名长度。这四个问题属于同一类 bug。
3. **方法成本低。** 只需要四个函数（`GenInput`、`Call`、`Maul`、`Match`）、一个把每个输入比特标为“必须影响输出”或“不得影响输出”的格式串、输入缓冲区前后各一个守卫字节，以及用来并行运行测试的 AFL++。一个 LibOQS 版本在 31–75 核上大约跑半天。
4. **有些发现不是 bug，论文也如实说明。** 多数 KEM 用 Fujisaki–Okamoto（FO）变换达到 IND-CCA 安全；在它的“隐式拒绝”形式下，密文合法时私钥的一部分不会被用到。随机化 Dilithium 忽略了私钥的一部分；有些公钥可以被修改而不影响验证。这些都不违反 IND-CCA 或 EUF-CMA（较弱的标准不可伪造性），但做了相反假设的协议可能出问题。
5. **它补充普通 fuzzing，而不是取代它。** 常规测试抓到了两个新方法漏掉的崩溃（Dilithium III 的 abort、Picnic_L3_UR 的段错误），因为新方法总是从一个固定的合法输入出发。

建议阅读路线：

1. 第 1–3 节讲普通测试为什么漏掉这些 bug、安全定义如何变成测试谓词。熟悉变形测试可以跳过。
2. 第 4–6 节是框架与 13 个测试。想自己搭 harness 的读者请细读。
3. 第 7–11 节是实验与案例分析，其中第 9 节最值得实现者读。
4. 第 12–15 节是我的评价、与 NGCC 首轮发现的对照、一个可改造的 harness 草稿和一份自查清单。

说明：本文是对论文的解读（[TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447)，[ePrint 2024/1122](https://eprint.iacr.org/2024/1122)，[代码](https://github.com/jangilcher/cryptoTesting)）。标注 \[source\] 的链接在写作时核对过；标注“*我的理解*”的段落是我的解读，不是论文的结论。引用前请复核原文。

本文是之前[《PQC 方案实现工程教程》](../pqc-implementation-guide/?lang=zh)的后续。那篇文章（第 7.1 节）列出了 PQC 实现需要的 11 个测试层次，本文详细介绍其中的第 6 层：性质与变异测试。第 13 节把论文的测试与那篇文章中的 NGCC 问题分类逐一对照。

## 1. 普通测试为什么漏掉这些 bug

测试一个原语的新实现 `P`，通常有两种办法：复现 KAT 向量，或者在随机输入上与参考实现 `P0` 比对（即差分测试）。两者都默认 `P0` 是对的。没有人测 `P0` 本身，因为它的输出被设计成“看起来随机”：给定 `t` 和 `P0(t)`，你没法判断 `P0(t)` 对不对。哈希函数更难，连可以对照的逆函数都没有。软件测试把这叫做 **oracle problem**（[Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)）。这里的测试预言机（test oracle）指判断输出是否正确的任何方法。

这件事重要，是因为参考实现会被反复复用：后续所有实现都拿它生成的 KAT 做校验，有时它还被直接部署。论文开头举了两个“纸面安全、实现出错”的例子：Java ECDSA 的 “psychic signatures”（[CVE-2022-21449](https://www.cve.org/CVERecord?id=CVE-2022-21449)），以及 Keccak 参考实现的缓冲区溢出（[CVE-2022-37454](https://www.cve.org/CVERecord?id=CVE-2022-37454)）。

fuzzing 有帮助，但只对表现为崩溃的 bug 有效。AFL++ 这类覆盖率引导的 fuzzer 会变异输入，保留能走到新代码路径的输入，并在程序崩溃、卡住或断言失败时报告。各类测试能发现的问题如下：

| 测试层 | 能观察到 | 看不到 |
| --- | --- | --- |
| KAT | 约 100 个 DRBG 输入上与参考实现一致 | 任何畸形或恶意输入上的行为 |
| 与参考实现差分 | 随机输入上与 `P0` 一致 | `P0` 自身也有的 bug |
| Sanitizer（ASan/UBSan/MSan） | 访问未分配内存、未定义行为 | 读到*相邻的合法*内存；任何逻辑缺陷 |
| 覆盖率引导 fuzzing | 崩溃、hang、断言失败 | 对篡改密文返回正确密钥的 `Decaps` |
| **密码学感知测试** | **违反既定输入/输出关系** | 需要结构化、多比特输入才能触发的 bug（见第 12 节） |

论文补的就是第四行的空白。把篡改密文解封装回原密钥的 KEM 运行得好好的；忽略某个输入比特的哈希函数也一样。要看见它们，测试程序必须知道这个原语**应该保证什么**。

## 2. 背景：变形测试与 Mouha 等人的工作

**变形测试**（[Chen、Cheung、Yiu，1998](https://arxiv.org/abs/2002.12543)；[Chen、Tse、Zhou，2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)）绕开了 oracle problem：你说不出一个输出对不对，但常常说得出**两个**输出之间应满足什么关系。一个测试用例如果没有明显失败，就是“不确定的”（indeterminate）；*变形关系*把不确定的用例变换成可以判定为失败的用例对。以哈希为例：你不知道 `H(x)` 应该是多少，但你知道 `H(x)` 和 `H(x ⊕ e_i)` 必须不同。

论文的起点是 Mouha、Raunak、Kuhn、Kacker（[IEEE Transactions on Reliability, 2018](https://doi.org/10.1109/TR.2018.2847247)）对 86 个 SHA-3 竞赛参考实现做的“事后验尸”，用了三条变形关系：

| 测试 | 关系 | 失败意味着 | 失败数 / 86 |
| --- | --- | --- | --- |
| **Bit-Contribution** | 对长度 ℓ 的输入逐位翻转，所有哈希值两两不同 | 某个输入比特没有影响输出 | 19 |
| **Bit-Exclusion** | SHA-3 要求支持非 8 整数倍的比特长度。ℓ ≡ 6 (mod 8) 时翻转最后一个字节中 2 个未用比特，哈希值必须**相同** | 实现读了不属于消息的比特 | 17 |
| **Update** | ℓ1 + ℓ2 = \|x\| 时 `Hash(x) = Final ∘ Update(ℓ2) ∘ Update(ℓ1) ∘ Init(x)` | 流式 API 与一次性哈希不一致 | 32 |

五个 SHA-3 决赛算法中有两个存在这类 bug。这些测试不需要任何规范，只需要“哈希应抗第二原像”和“未用比特就是未用”两句话。

## 3. 把安全定义写成测试谓词

从 Mouha 等人走到 KEM 和签名，关键一步是注意到：每个安全游戏都有一种廉价、具体的反例形态。你不需要聪明的敌手，只需要一对游戏声称“不可能出现”的输入。

| 安全性质 | 一句话游戏 | 一个反例就够 | 对应测试 |
| --- | --- | --- | --- |
| 第二原像抵抗 | 给定随机 `x`，找 `x' ≠ x` 使 `H(x') = H(x)` | `x' = x ⊕ e_i` 得到相同摘要 | Test 1 |
| **IND-CCA**（KEM） | 在一个只拒绝 `c*` 的解封装预言机帮助下，区分 `ss*` 与随机值 | `c' = c* ⊕ e_i` 解封装出 `ss*`。提交 `c'`、与挑战值比较，以概率 1 获胜 | Test 7 |
| **sUF-CMA**（签名） | 看过若干签名后，输出一个*新的*合法对 `(m*, σ*)`，“新”指这一对从未被返回过 | `σ' = σ ⊕ e_i`（或换一个长度的 `σ`）对 `m` 仍然验证通过 | Test 13 |
| EUF-CMA | 同上，但 `m*` 必须是新消息 | 单比特翻转测不了，论文也没有声称 | 无 |

IND-CCA 这一行值得展开。游戏中敌手拿到 `c*` 和一个“要么是 `ss*`、要么是随机值”的密钥，外加一个能解封装除 `c*` 以外任何密文的预言机。如果翻转 `c*` 的一位得到的密文仍能解封装出 `ss*`，敌手就把 `c'` 交给预言机，拿回 `ss*` 直接比较。方案是被彻底打破，而不是有一点点优势。所以对一个声称 IND-CCA 的方案，**哪怕一个** Test 7 反例也是实打实的 bug。

sUF-CMA 这一行更微妙。NIST 并不要求强不可伪造，很多候选也没有声称。但有些构造本身**蕴含**它（Falcon 使用的 GPV hash-and-sign 框架，由 [Gentry、Peikert、Vaikuntanathan](https://eprint.iacr.org/2007/432) 提出），有些协议也依赖它，比如把签名当作交易或消息的唯一标识。所以：方案声称或其构造应当提供该性质时，违反是 bug；否则是隐患。

## 4. 从哈希到 KEM 与签名

搬到 KEM 和签名上，可测的东西更多，也多了四个实际差异。

**函数更多，彼此有结构。** 哈希只有一个函数；KEM 有 `(Gen, Encaps, Decaps)`，签名有 `(Gen, Sign, Verify)`。它们可以组合：“用篡改公钥封装，再用原私钥解封装”就是哈希给不了的一条有意义的关系。

**随机性。** `Gen`、`Encaps`、`Sign` 都会读取随机带（random tape），即算法消耗的随机字节序列。测试中这些字节来自一个由种子初始化的伪随机数生成器（PRG）。论文分两种情况处理：

- 篡改的是*其他*输入（比如 `Encaps` 的 `pk`）时，固定 PRG 种子，保证可复现。
- 篡改的是*随机带本身*时，换种子只是换一组随机数，测不到什么。于是他们装上一个**永远输出同一个字节的坏 PRG**，让这个字节从 0 走到 255。这超出了所有安全模型，但能暴露随机带“不走运”时死循环的实现，比如一直拒绝候选值的密钥生成。LibOQS 支持自定义 RNG，接入很容易。

**输入大多定长。** KEM 和签名的输入大多长度固定。例外是：随机带（用定长种子处理）、消息（固定为某个值，因为消息会先被哈希，测不同长度只是在测哈希），以及变长签名。对变长签名，签名放在一个能容纳最长签名的缓冲区里，旁边是记录其字节长度 `ℓσ` 的字段，**`σ` 和 `ℓσ` 都会被篡改**。正是这个细节抓到了 CROSS（9.6 节）。

**返回值。** 教科书里的 KEM、签名语法没有返回码，实现却大量依赖它：`Verify` 用它表示接受/拒绝，不少 KEM 用它表示显式拒绝。论文把返回值 `rv` 算作每个输出的一部分，例如 `Gen` 输出 `(pk, sk, rv)`。脚注指出，LibOQS 文档说返回值只报告意外错误，与代码的实际行为不符。

另外，NIST 没有规定 PQC 提交的内部 API，因此没有 Update 测试的对应物。

## 5. 框架：四个函数、一个循环

工程目标是让库维护者以很低的成本接入。论文因此把一个**变形测试规范**定义为四个函数 `Φ = (GenInput, Call, Maul, Match)`：

| 函数 | 签名 | 作用 |
| --- | --- | --- |
| `GenInput` | `(Π, pp, fmt) → (x, y, aux)` | 生成合法输入 `x`、基准输出 `y`，以及不被篡改的数据 `aux`（例如篡改 `c` 时的 `sk`） |
| `Call` | `(Π, x, aux, pp, fmt) → y` | 调用被测方法 |
| `Maul` | `(x, fmt, σ) → (x', σ', expected)` | 生成下一个篡改输入，并给出输出应*相同*还是*不同* |
| `Match` | `(y, y', expected) → ok / abort` | 比较，结果不符就崩溃 |

![测试循环：GenInput 生成基准输出，Maul 翻转一个比特并给出期望，Call 重新调用函数，Match 不符时 abort，AFL++ 保存触发崩溃的输入](./diagrams/test-loop.svg)

驱动程序就是普通的 fuzz 循环：

```text
Test(Π, pp, fmt, runs, σ0):
  sus ← []; σ ← σ0
  (x, y, aux) ← GenInput(Π, pp, fmt)
  for i in 1..runs:
      (x', σ', expected) ← Maul(x, fmt, σ);  σ ← σ'
      try:
          y' ← Call(Π, x', aux, pp, fmt)
          Match(y, y', expected)          # 不符则 abort
      catch:
          sus.append((x, fmt, σ))
  return sus
```

全文只有一个 `Match`：两个输出 `(d, rv)` 与 `(d', rv')` 在数据和返回值都相等时才算相等，相等与否和期望不符就 abort。`Match` 和 `Maul` 的大部分与原语无关，可以原样复用；`Call` 和 `GenInput` 在各测试之间也共享大部分结构。

与 Mouha 等人有一处刻意的不同：循环每次只比较**一对** `(y, y')`，而不是收集一大堆输出找碰撞。原因很实际：成对比较可以写成 AFL++ 的自定义 mutator（由用户提供、AFL++ 调用来生成下一个输入的函数），于是可以直接使用 AFL++ 的并行执行、崩溃保存和复现功能。`Match` 一 abort，AFL++ 就把它记成一次崩溃。

论文明确说，形式化框架只是统一术语；真正的贡献是那批**带着密码学知识写成的待 fuzz 程序**：恰好在密码学性质失效时崩溃。

### 5.1 类型

C 实现用几个抽象类型对应 `Φ`：

| 类型 | 含义 | 内容 |
| --- | --- | --- |
| `in_t` | 输入 `x` | 字节缓冲区指针 + 字节长度 |
| `out_t` | 输出 `y` | 字节缓冲区 + 长度 + 整数返回值 |
| `aux_t` | 辅助数据 | 带长度的字节缓冲区列表 |
| `pp_t` | 公开参数 | 对 LibOQS 而言只是算法标识 |
| `fmt_t` | 格式串 | `(比特长度, 标签)` 列表 |
| `exp_res_t` | 期望 | 布尔值：输出应相等或不等 |

### 5.2 格式串与守卫字节

这是全文最有用的一个设计。格式串是 `(ℓ, 标签)` 的列表，标签为 `DIFF`（翻转这里的比特，输出必须变）或 `EQ`（翻转这里的比特，输出不能变）。一个格式串同时表达了 bit-contribution 和 bit-exclusion。

论文的例子：一个 14 bit 的哈希输入存在 2 字节里，第二个字节的最后 2 bit 不属于消息。前后各加一个守卫字节：

```text
fmt = [(8, EQ), (14, DIFF), (2, EQ), (8, EQ)]
```

测试程序传给被测函数的是 `&x[1]`，而不是 `&x[0]`。守卫字节初始化为 `0xFF`。翻转任何消息比特，摘要必须变；翻转两个填充位之一或任一守卫字节的任何比特，摘要不能变。变了，就说明实现读了输入之外的内存。

论文中所有 KEM 和签名测试都用同一形状：`[(8, EQ), (|input|, DIFF), (8, EQ)]`。

![Test 7 的缓冲区布局：一个守卫字节、标为 DIFF 的密文（包括最后一个字节的填充位）、一个尾部守卫字节；翻转守卫字节输出必须不变，翻转任何密文比特输出必须改变](./diagrams/buffer-layout.svg)

*我的理解：* 守卫字节能抓到 sanitizer 漏掉的一类 bug。ASan 报告的是对未分配或被毒化内存的读；读到一个更大的合法分配中的下一个字节，它是看不见的，而 KNOT-384 正是这样（9.2 节）。

### 5.3 Maul 的调度

大多数测试共用一个 `Maul`（论文 Figure 4），状态 `σ` 从 −3 开始：

| σ | 篡改方式 | 期望 |
| --- | --- | --- |
| −3 | 不改 | 相同（固定种子下函数是否确定） |
| −2 | 整个缓冲区置全 0 | 只要某个 `DIFF` 字节变了，就应不同 |
| −1 | 整个缓冲区置全 1 | 同上 |
| 0, 1, 2, … | 翻转第 σ 位 | 由第 σ 位所在区域的标签决定 |

篡改随机带的测试（Test 2、5、10）用更简单的 `Maul`：坏 PRG 重复一个字节，`σ` 就是这个字节，从 0 到 255，每个取值都应得到不同输出。

## 6. 十三个测试

| # | 被测调用 | 篡改对象 | 必须成立 | 代码中的报告名 |
| --- | --- | --- | --- | --- |
| 1 | `Hash(Maul(x))` | 消息 + 守卫字节 | 当且仅当消息比特变化时摘要变化 | （SUPERCOP） |
| 2 | `Gen(; Maul(r))` | 随机带 | 不同随机带得到不同密钥；不 hang | `KEM/Keygen/badrng`、`SIGN/Keygen/badrng` |
| 3 | `Encaps(Maul(pk); r)` | 公钥 | `(ss, c)` 变化 | `KEM/Encaps/pk-0` |
| 4 | `Decaps(sk, Encaps(Maul(pk); r))` | 公钥 | 用原 `sk` 解封装不能得到同一个密钥 | `KEM/Encaps/pk` |
| 5 | `Encaps(pk; Maul(r))` | 随机带 | `(ss, c)` 变化 | `KEM/Encaps/badrng` |
| 6 | `Decaps(Maul(sk), c)` | 私钥 | 共享密钥变化 | `KEM/Decaps/sk` |
| 7 | `Decaps(sk, Maul(c))` | 密文 | 共享密钥变化（**IND-CCA**） | `KEM/Decaps/c` |
| 8 | `Sign(Maul(sk), m; r)` | 私钥 | 签名变化 | `SIGN/Sign/sk` |
| 9 | `Sign(sk, Maul(m); r)` | 消息 | 签名变化 | `SIGN/Sign/m` |
| 10 | `Sign(sk, m; Maul(r))` | 随机带 | 签名变化（确定性方案预期会碰撞） | `SIGN/Sign/badrng` |
| 11 | `Verify(Maul(pk), m, σ)` | 公钥 | 验证失败 | `SIGN/Verify/pk` |
| 12 | `Verify(pk, Maul(m), σ)` | 消息 | 验证失败 | `SIGN/Verify/m` |
| 13 | `Verify(pk, m, Maul(σ))` | 签名及其长度 | 验证失败（**sUF-CMA**） | `SIGN/Verify/sig` |

报告名取自[仓库 README](https://github.com/jangilcher/cryptoTesting) \[source\]，读生成的报告时很有用。

几个测试值得细看：

- **Test 4** 组合了两个函数：在篡改公钥 `pk'` 下封装，再用*原* `sk` 解封装，检查两个共享密钥不同。碰撞意味着 `pk` 的某些比特从未影响密文所承诺的内容。
- **Test 6** 是 FO 隐式拒绝现身的地方（10.1 节）。在正确实现上也会有大量命中。
- **Test 10** 对确定性方案反转了期望：换随机带*不应*改变确定性签名，所以这里的碰撞是正常的。
- **Test 13** 有自己的 `Maul`，格式为 `[(|ℓσ|, DIFF), (8, EQ), (|σ|, DIFF), (8, EQ)]`：先把长度字段依次设为每个小于真实长度的值，再逐位翻转签名。忽略长度的方案会在截短的长度下验证通过，CROSS 就是这样被抓到的。

## 7. 实验设置

**硬件。**

| 机器 | CPU | 核数 | 内存 |
| --- | --- | --- | --- |
| A | 2 × Intel Xeon Gold 6138，2.00 GHz | 40 | 376 GiB |
| B | 4 × Intel Xeon Gold 6252，2.10 GHz | 96 | 754 GiB |
| C | 1 × AMD EPYC 7742，2.25 GHz | 64 | 503 GiB |

**AFL++ 配置。** 改了三处默认值：

- 输入大小上限从 1 MB 提到 10 MB，因为有些公钥非常大。
- 关闭所有内置变异器，换成一个自定义的单比特翻转 mutator。AFL++ 不能单独关闭某个内置变异器，自定义 mutator 是唯一办法。
- 每个目标最多保存 10 个不同崩溃，避免产生 TB 级数据。

作者直说：用 AFL++ 主要是为了崩溃处理和存储，换别的 fuzzer 也行。*我的理解：* 变异器被换成确定性调度之后，AFL++ 实际上是一个并行测试运行器，覆盖率引导基本不起作用。

**被测对象。**

- LibOQS 0.14.0（2025 年 7 月）、0.8.0（2023 年 6 月）、0.4.0（2020 年 8 月），以及 2018 年 11 月的 `nist-branch` 快照。
- SUPERCOP 20240107 中的哈希函数。SUPERCOP 是一个基准测试套件，用统一 API 收录了大量实现。

为什么测旧版本？LibOQS 会随着方案在 NIST 进程中被淘汰而删除它们，只测最新版能覆盖的方案很少。四个快照合起来包含了提交给 NIST PQC 的大部分参考实现。作者认为自动化测试应当尽早使用，所以测不成熟的代码正是目的所在。

**基线。** 一组没有语义知识的 AFL++ harness：把二进制文件解析成函数输入，并保证定长输入长度正确。密钥生成没有直接输入，所以基线不覆盖 `Gen`。

**计数规则。** 结果按（方案, 参数集, LibOQS 版本）分别计数，同一组合内的多个触发输入只算一次。如果同一行代码在 0.4.0 和 0.8.0 的 `XYZ-128`、`XYZ-256` 中都触发 bug，就算四次。计数是自动完成的，没有人工归因。所以总数衡量的是*受影响的组合*，不是*独立 bug 数*。

## 8. 结果概览

### 8.1 基线的崩溃与 hang

| 库 | KEM Encaps | KEM Decaps | DSS Sign | DSS Verify | 耗时 | 机器（核数） |
| --- | --- | --- | --- | --- | --- | --- |
| LibOQS 0.14.0 | 0 | 0 | 0 | 0 | 2h | A (31) |
| LibOQS 0.8.0 | 0 | 0 | 0 | 0 | 27m | C (50) |
| LibOQS 0.4.0 | 8 | 0 | 9（1 hang） | 0 | 57m | C (50) |
| LibOQS nist-branch 2018-11 | 10 | 12（1 hang） | 5 | — | 23m | B (75) |
| SUPERCOP 20240107（哈希） | 4 | | | | 8h 6m | C (50) |

KEM 崩溃从最老版本到 0.4.0 严格下降：`nist-branch` 中的崩溃在 0.4.0 全部消失，0.4.0 的崩溃全部来自 `nist-branch` 中还不存在的方案。签名崩溃在 0.4.0 反而上升，看起来是多个 Picnic 变体的回归。0.8.0 起，普通 fuzzing 什么都找不到。

### 8.2 密码学感知测试的开销

| 库 | 耗时 | 机器（核数） |
| --- | --- | --- |
| LibOQS 0.14.0 | 12h 40m | B (75) |
| LibOQS 0.8.0 | 14h 23m | A (31) |
| LibOQS 0.4.0 | 12h 43m | A (31) |
| LibOQS nist-branch 2018-11 | 8h 59m | A (31) |
| SUPERCOP 20240107 | 6h 58m | A (31) |

每个库约半天。对标准化项目或大型库来说，放进每晚或每周任务完全可行。

### 8.3 总量

- **200 多个可塑性**：改了一个输入，输出没变。
- **48 个 hang、50 个段错误、3 个堆溢出、2 个栈溢出**，均由篡改某个预期输入触发。

并非每个可塑性都是 bug（第 10 节）。内存错误是否构成漏洞，取决于 API 的暴露程度。

### 8.4 逐项结果（论文 Table 3）

“可塑”统计 bit-contribution 失败（输出没变），“非可塑”统计 bit-exclusion 失败（不该变的时候变了）。没有结果的测试省略。

**SUPERCOP 20240107**

| 测试 | 可塑 | 崩溃/hang | 非可塑 |
| --- | --- | --- | --- |
| 1 | 3 | 0 | 3 |

**LibOQS 0.14.0（2025/07）**

| 测试 | 可塑 | 崩溃/hang | 非可塑 |
| --- | --- | --- | --- |
| 5 | 1 | 10（hang） | 0 |
| 6 | 26 | 0 | 0 |
| 8 | 11 | 0 | 0 |
| 11 | 10 | 0 | 0 |
| 13 | 25 | 0 | 0 |

**LibOQS 0.8.0（2023/06）**

| 测试 | 可塑 | 崩溃/hang | 非可塑 |
| --- | --- | --- | --- |
| 3 | 10 | 0 | 0 |
| 4 | 10 | 0 | 0 |
| 5 | 1 | 10（hang） | 0 |
| 6 | 23 | 0 | 0 |
| 8 | 3 | 0 | 0 |
| 13 | 2 | 0 | 0 |

**LibOQS 0.4.0（2020/08）**

| 测试 | 可塑 | 崩溃/hang | 非可塑 |
| --- | --- | --- | --- |
| 3 | 23 | 8（段错误） | 0 |
| 4 | 31 | 8（段错误） | 0 |
| 5 | 1 | 10（hang） | 0 |
| 6 | 51 | 0 | 0 |
| 7 | 10 | 0 | 0 |
| 8 | 10 | 3（堆溢出）+ 1（hang） | 0 |
| 9 | 0 | 1（hang） | 0 |
| 10 | 22 | 1（hang） | 0 |
| 11 | 7 | 1（hang） | 0 |
| 12 | 0 | 1（hang） | 0 |
| 13 | 9 | 1（hang） | 0 |

**LibOQS nist-branch 2018-11**

| 测试 | 可塑 | 崩溃/hang | 非可塑 |
| --- | --- | --- | --- |
| 2 | 3 | 0 | 0 |
| 3 | 4 | 6（段错误）+ 1（返回 ⊥） | 0 |
| 4 | 9 | 7（段错误）+ 1（hang） | 0 |
| 6 | 24 | 12（段错误）+ 7（hang） | 0 |
| 7 | 3 | 9（段错误）+ 2（栈溢出）+ 4（hang） | 0 |
| 10 | 6 | 0 | 0 |

两点值得注意。每个版本里 Test 6 的计数都最大，主要来自 FO 的“特性”（10.1 节）。最新的 0.14.0 里 Test 13 有 25 次命中：强不可伪造是当前代码中最常缺失的性质。

论文也讨论了 hang：有时 hang 比在不报错的情况下使用坏随机数更好。更好的办法是对随机源做健康测试，但这本身也有难点。

## 9. 案例分析

每个案例依次给出：现象、哪个测试抓到、根因、以及自己代码里该查什么。

### 9.1 NTRU：不检查填充位，IND-CCA 被打破

**现象。** LibOQS 0.4.0 中的 NTRU-HRSS-701、NTRU-HPS-2048-677、NTRU-HPS-2048-509：翻转密文的一位，仍解封装出原共享密钥。由 Test 7 抓到。

**根因。** 密文打包了 `n − 1` 个系数，每个 `log q` 比特，总比特数不是 8 的倍数：

| 参数集 | 打包比特数 | 密文字节数 | 最后一个字节的未用比特 |
| --- | --- | --- | --- |
| HPS-2048-509 | 508 × 11 = 5588 | 699 | 4 |
| HPS-2048-677 | 676 × 11 = 7436 | 930 | 4 |
| HRSS-701 | 700 × 13 = 9100 | 1138 | 4 |

规范中的 `bits_to_bytes` 会零填充到字节边界，但解封装没有检查这些填充位。解包时高 4 位被忽略，所以无论那里取什么值，解出的都是同一个多项式。[修复提交](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) \[source\]（2020 年 1 月，致谢 Fernando Virdia 与 Greg Zaverucha）在解密前加了一行：

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

以 HPS-2048-509 为例，`7 & 5588 = 4`，掩码是 `0xF0`：高 4 位必须为零。

*我的理解：* 同一个提交也说明了为什么通常的 FO 重加密检查没有发现这个问题。修复旁边的注释写着：解密成功时 `c = Enc(h, rm)` 已经成立，“无需重新封装”。但这个等式成立在解包后的多项式上，而不是字节上。按字节做重加密比较本可以抓到填充位；代数上的捷径把它跳过了。如果你绕过重加密，你就有义务证明编码在字节层面是单射。

**自查。** 每个非字节对齐的打包，解码时都必须拒绝非零填充。带守卫字节的 Test 7 可以自动覆盖。

### 9.2 KNOT-384：输出依赖消息后面的那个字节

**现象。** KNOT-384 哈希（NIST 轻量级密码竞赛第一轮）的优化实现中，长度为 6 字节倍数的消息，其哈希值会随内存中紧跟消息的第一个字节而变化。由 Test 1 的尾部守卫字节抓到，属于 bit-exclusion 失败。

**根因。** 在“低位优先 / 高位优先”整数表示之间转换时掩码写错。

**披露。** 设计者在后续轮次的提交中修复了它，但没有公开说明，SUPERCOP 中的副本也没有更新。其实 SUPERCOP 曾报告 KNOT-384 输出“非确定”（[存档报告](https://web.archive.org/web/20200810000404/https:/bench.cr.yp.to/web-impl/amd64-pmnod003-crypto_hash-knot384.html)），只是没人把它和越界读联系起来。

**自查。** 在每个分组、字边界附近的长度上，给每个输入缓冲区加守卫字节测试。sanitizer 看不到这类问题。

### 9.3 acehash 与 syconhash：SIMD 代码中的第二原像

SUPERCOP 中三个哈希实现不满足第二原像抵抗：`acehash256v1`（SSE2）和 `syconhash256v1`（AVX、SSE）。基线在同样的实现上看到了非法读导致的段错误，作者认为两者很可能同源。论文强调这些是特定实现的 bug，与设计无关。

*我的理解：* 这些是正确参考设计的向量化版本。在随机输入上与参考实现做逐 kernel 差分，未必能抓到“某条 lane（SIMD 寄存器中的一个槽位）忽略了一个输入比特”的实现，因为随机输入恰好只在那一位上不同的概率很低。bit-contribution 测试会翻转每一个输入比特，因此一定能发现。

### 9.4 Falcon：零有两种编码

**现象。** LibOQS 0.4.0 中的 Falcon 不提供强不可伪造，测试时的 LibOQS 0.14.0 也一样。由 Test 13 抓到。

**根因。** Falcon 压缩签名格式把每个系数编码为一个符号位、低 7 位、以及一元编码的高位。解码器接受 `100000001`（“−0”）作为 0 的合法编码，也不检查签名是否用零填充。两者都能产生解码为同一签名的第二种字节串。这在 2022 年 11 月以 [liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315) \[source\] 报告，引用了 Falcon 规范 v1.2 的 3.11.2 节和算法 17–18。

**为什么重要。** Falcon 是 GPV hash-and-sign 方案，而 GPV 蕴含强不可伪造（[GPV08](https://eprint.iacr.org/2007/432), Prop. 6.1）。Falcon 设计文档没有说明该性质缺失，用户有理由默认它成立。Falcon 团队已独立发现并在规范 v1.2 中修复；披露后不久，LibOQS 也更新了它的副本。

### 9.5 SNOVA：尾部未用比特

在 LibOQS 0.14.0 中，SNOVA 的部分参数集签名最后一个字节没有用满，未用比特取任何值都会被接受。与 NTRU 同类：非字节对齐编码，没有检查填充。

### 9.6 CROSS：被忽略的长度

**现象。** PQClean 是一个收录可移植 PQC 实现、并统一其 API 的项目。在 PQClean 兼容的 CROSS 实现中，任何合法签名在尾部追加字节后仍能验证通过。由 Test 13 的长度篡改抓到。

**根因。** PQClean API 会把签名长度传给 `crypto_sign_verify`。CROSS 的签名定长，其实现忽略了这个参数；其他 PQClean 实现（ML-DSA、SPHINCS+）都会拒绝错误长度。2025 年 9 月以 [CROSS-lib-oqs issue #1](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) \[source\] 报告。

提交给 NIST 的实现没有这个 bug，因为那里已经有类似的测试。*我的理解：* 这提醒我们，算法的每一种封装（NIST API、PQClean API、liboqs 包装）都是一份独立的实现，都需要自己的负向测试。

### 9.7 会崩溃的解封装就是预言机

在 `nist-branch` 2018-11 中，Big Quake、LEDAkem、LIMA 在解封装篡改密文时会崩溃或 hang。崩溃是一种可观察的差异，因此构成**密文合法性预言机**：攻击者能得知一个密文是否合法。针对 FO 类 KEM 的明文检查攻击正是利用这类泄露：攻击者发送构造的密文，用每次“是/否”的结果逐步获得私钥信息。

### 9.8 不是 bug：本就不声称 IND-CCA 的方案

Test 7 也会在 LibOQS 0.4.0 的 ephemeral ThreeBears、SIKE 变体，以及 `nist-branch` 中的一个 BIKE 变体上命中。这些变体不声称 IND-CCA，测试只是如实反映了设计。测试套件应当允许把它们标记为预期结果。

## 10. “特性”：不是 bug，但出人意料

标题里的 “Features” 指的就是这一部分，也是我觉得最有意思的部分。这些性质来自方案定义，而非实现错误。它们不打破 IND-CCA 或 EUF-CMA，但做了相反假设的协议或密钥管理系统可能会出问题。

### 10.1 FO 隐式拒绝下，KEM 私钥是可塑的

很多 KEM 用 [Fujisaki–Okamoto 变换](https://doi.org/10.1007/3-540-48405-1_34)从被动安全方案构造 IND-CCA 安全。在隐式拒绝变体中（[Hofheinz–Hövelmanns–Kiltz](https://eprint.iacr.org/2017/604)），私钥带一个随机串 `z`，只在密文非法时用来派生伪随机密钥。以 ML-KEM 解封装（FIPS 203 算法 18）为例：

```text
m'      ← K-PKE.Decrypt(dk_PKE, c)
(K', r') ← G(m' || h)
K̄       ← J(z || c)          # 拒绝密钥
c'      ← K-PKE.Encrypt(ek, m', r')
if c ≠ c': K' ← K̄
return K'
```

![FO 隐式拒绝：合法密文的输出密钥来自 G(m' || h)，拒绝密钥 J(z || c) 虽被计算却被丢弃，因此修改 z 不改变输出](./diagrams/fo-implicit-rejection.svg)

对合法密文，`J(z || c)` 会被计算然后丢弃。之所以总是计算它，是为了让运行时间不依赖于密文是否合法。翻转 `z` 的任何一位，解封装返回的仍是同一个密钥。论文把 LibOQS 0.8.0 和 0.4.0 中 IND-CCA KEM 的所有 Test 6 命中都归因于此。

**会在哪里出问题。** 如果一个系统用“这把私钥能正确解封装”来校验存储的私钥，它会接受一把 `z` 已损坏的私钥，而损坏只有在非法密文到来时才会暴露。*我的理解：* FIPS 203 在解封装输入校验中加了私钥哈希检查，覆盖的是 `h = H(ek)` 那一部分；`z` 的完整性仍需另行保证。

### 10.2 随机化 Dilithium 忽略了私钥的一部分

Dilithium 私钥中有一个 256 bit 的 `K`。确定性变体用 `K` 和消息派生签名随机性；随机化变体直接采样新的随机数，忽略 `K`。两者共用一种私钥格式。测试中 RNG 种子是固定的，于是只在 `K` 上不同的两把私钥会产生完全相同的签名（Test 8）。在实际部署中，只有签名随机源出故障时才会观察到。

*我的理解：* ML-DSA（FIPS 204）改变了这一点。其 hedged 签名（把新的随机数 `rnd` 与私钥材料混合）把签名种子派生为 `ρ'' ← H(K || rnd || μ)`，`K` 在两种模式下都有贡献。在 ML-DSA 上重跑 Test 8，可以低成本确认这个性质已经消失。

### 10.3 可以被修改的公钥：排他所有权

在 LibOQS 0.4.0 中，Rainbow 和 Falcon 的公钥可以被改成另一个 `pk' ≠ pk`，使合法的 `(pk, m, σ)` 换成 `(pk', m, σ)` 后仍验证通过（Test 11，现已解决）。这类似于打破**保守排他所有权**（CEO，[Pornin–Stern 2005](https://doi.org/10.1007/11496137_10)）：给定一个合法签名，找到另一个能验证它的公钥。这里攻击者拿不到 `pk'` 的私钥，因此排除了冒名攻击；但它满足**强**变体的条件，即 S-CEO（[Cremers 等，“BUFFing signature schemes”，S&P 2021](https://eprint.iacr.org/2020/1525)）和 S-UEO（[Brendel 等，S&P 2021](https://eprint.iacr.org/2020/823)），这两者不要求敌手知道对应的私钥。

这在实际协议中影响多大尚不清楚，论文也没有夸大。[Jackson 等（CCS 2019）](https://eprint.iacr.org/2019/779)表明，这类微妙的签名性质确实会打破使用经典签名的真实协议，所以对 PQC 也值得追问。

## 11. 与基线逐项对比

| 库 | 两者都发现 | 只有密码学感知测试发现 | 只有基线发现 |
| --- | --- | --- | --- |
| LibOQS 0.4.0 | SIKE/SIDH 压缩变体在 `Encaps` 中段错误 | 10 个 IND-CCA 反例；9 个 sUF-CMA 反例；3 个 Picnic 缓冲区溢出 | 无：基线的 9 个 Picnic `Sign` 段错误中，有 6 个变体被新测试通过随机带测试识别 |
| LibOQS nist-branch 2018-11 | 全部 12 个 `Decaps` 段错误、`Decaps` 的 hang、全部 5 个 `Encaps` 段错误 | 3 个 IND-CCA 反例 | **Dilithium III 的 abort；Picnic_L3_UR 的段错误** |
| LibOQS 0.8.0 | — | 2 个 sUF-CMA 反例 | — |
| LibOQS 0.14.0 | — | 25 个 sUF-CMA 反例 | — |
| SUPERCOP 20240107 | acehash256v1（AVX、SSE2）与 syconhash256v1（AVX、SSE）段错误，均为非法读 | 第二原像失败，很可能同源 | — |

合计：基线没发现的 **13 个 IND-CCA 反例和 36 个 sUF-CMA 反例**，外加 S-CEO/S-UEO 类性质。作者认为换一个更强的基线 fuzzer 也不会改变这一点，因为违反安全定义本身不会崩溃，只有编码了该定义的 harness 才能看见。他们把密码学感知测试定位为传统 fuzzing 和编译器检查选项的补充，而非替代。

## 12. 评价

### 12.1 做得好的地方

- **方法简单，结果实在。** 不需要符号执行，也不需要形式化模型。“篡改密文不能解封装出原密钥”这样一句话就变成可执行检查，并找到了真实的、已被修复的 bug。
- **格式串是一个好的抽象。** 一个 `(长度, 标签)` 列表同时表达“这些比特必须有影响”和“这些比特必须无影响”，守卫字节还能在不增加代码的情况下检测越界读。可以跨原语、跨库复用。
- **它点出了一类 bug。** NTRU、Falcon、SNOVA、CROSS 是同一模式：解码器对同一个对象接受不止一种字节串。规范往往只用半句话说明规范形式（“填充位为零”），代码里很容易漏，测试起来却很简单。
- **诚实地区分 bug 与特性。** 200 多个可塑性没有被包装成 200 个漏洞；论文区分了实现 bug、有意为之的性质和出人意料的性质。
- **易于接入。** LibOQS 和 SUPERCOP 共用 SUPERCOP 风格 API，测试代码只需少量适配。作者建议把这些测试作为可选模式加入 SUPERCOP 和 [Project Wycheproof](https://github.com/C2SP/wycheproof)（Google 维护的已知攻击测试向量集），我同意。

### 12.2 局限与可以追问的地方

- **变异集合很窄。** 单比特翻转、全 0、全 1，以及 256 个坏 RNG 字节。需要两处协同修改（例如保持内部校验和合法）或结构化取值（等于 `q` 的系数、乱序的 hint 下标）的 bug 无法覆盖。用到的变形关系也只有“相等/不等”一种。
- **覆盖率引导没有用上。** 变异调度是确定性的，AFL++ 只是运行器。这是设计选择而非缺陷，但这里的 “fuzzing” 更接近穷举式变形测试，而非覆盖率引导探索。
- **每个测试只有一个起点。** 每个测试都从固定种子生成的一个合法输入出发。需要特定密钥或消息才能触发的 bug（罕见的拒绝采样分支、边界系数）可能被漏掉。基线抓到了新测试漏掉的两个崩溃，与此一致。
- **计数的是受影响组合。** 按（方案, 参数集, 版本）计数并包含有意为之的性质，会放大总数。引用时请引用具体案例，而不是“200+”。
- **哈希只有一个测试。** 近碰撞、输出均匀性留作未来工作，Update 测试也没有 PQC 对应物。
- **目标大多是历史版本。** 这是有意的，也说得通，但结果反映的更多是标准化过程中的实现质量，而非今天的生产库。0.14.0 上 Falcon、SNOVA、CROSS 的发现说明较新的代码也有同样的问题。

### 12.3 我会补充什么

*我的理解*，以写优化 kernel 的人的视角：

1. **在比特翻转之外加结构化篡改。** 对格密码方案，把打包字段里的某个系数编码成 `q`、`q + 1` 或 `2^k − 1`，交换两个 hint 下标，把长度设成最大值。它们正好针对 FIPS 203/204 新增的“解码必须单射”检查（模数检查、hint 顺序）。
2. **在每个后端上跑同一个格式串。** ref、AVX2、AVX-512、Cortex-M4 在每个篡改输入上都应返回相同的字节*和*相同的返回码。不一致要么是 bug，要么是不同分发路径之间的行为差异。
3. **与恒定时间检查结合。** 论文建议使用 [dudect](https://eprint.iacr.org/2016/1123)，它测量两类输入的运行时间并做统计检验。成本更低的第一步是：在 Valgrind 下运行 Test 7 的循环，把私钥标记为未定义内存，Valgrind 会报告所有依赖它的分支和内存地址。每个篡改密文都会走拒绝路径，而 FO 的时序泄露通常出现在这条路径上。
4. **在 CI 里放一个小预算。** 只跑 Test 7 和 Test 13、只跑默认参数集，几分钟就能完成，覆盖最要紧的两条性质。

## 13. 与 NGCC 首轮发现的对照

在之前的[PQC 方案实现工程教程](../pqc-implementation-guide/?lang=zh)里，我把 NGCC 首轮公开评审的 65 条实现类发现分成了 9 类。下表是这些测试能抓到哪些、抓不到哪些。

| NGCC 类别（前文 5.1 节） | 能否覆盖 | 测试 | 说明 |
| --- | --- | --- | --- |
| 1. 安全预算被代码截断 | 否 | — | 长度错误不改变某个比特是否有影响，需要对参数做静态断言 |
| 2. FO 变换实现错误 | **能** | 7、6 | “只比较每第 4 个字节”（kem-02-1）正是一个 Test 7 可塑性 |
| 3. 随机性问题 | 部分 | 2、5、10 | 坏 RNG 测试能找到 hang；“两次调用必须不同”就是把 −3 步的期望反过来，很容易加上 |
| 4. 输入解析与内存安全 | **能** | 3、4、6、7、11–13 | 篡改下的段错误与溢出；守卫字节还能抓越界读 |
| 5. 编码非单射 / 可塑性 | **能** | 7、11、13 | 即 NTRU/Falcon/SNOVA/CROSS 这一类 |
| 6. 代码与 spec 不一致 | 否 | — | 需要独立可执行模型和中间值比对 |
| 7. 状态管理 | 否 | — | 有状态 API 不在语法范围内 |
| 8. 协议层遗漏 | 否 | — | 超出原语范围 |
| 9. 残留调试代码 | 很少 | — | 只有改变输出时才能发现 |

大致而言：凡是能表述成“这个输入必须/不能影响那个输出”的类别，这些测试都能覆盖；它们替代不了一个独立的规范模型。

前文也引用过 KpqC 首轮分析（[ePrint 2023/1437](https://eprint.iacr.org/2023/1437)），它已经把变形测试用在了韩国候选上。这篇论文给这种做法提供了一个可复用的形式。

## 14. 一个可以改造的最小 harness

[作者的代码](https://github.com/jangilcher/cryptoTesting)在 Docker 中运行：`bash run.sh` 打开容器，`bash reproduce.sh ches_liboqs` 复现 LibOQS 0.14.0 的实验（0.8.0 用 `cur_liboqs`，0.4.0 用 `mid_liboqs`，2018-11 用 `old_liboqs`，哈希用 `supercop`；末尾加 `baseline` 则跑普通 AFL++ 基线）\[source\]。README 提醒：hang 的计数取决于 CPU 速度，越界写也不一定导致段错误，所以复现出的数字可能略有不同。

如果只想在自己的库上跑 Test 7 和 Test 13，不需要 AFL++。下面的草稿使用 liboqs 公开 API 和确定性 RNG。**这是草稿：我没有针对某个具体 liboqs 版本编译过，请对照你所用版本的 API。** 省略了错误处理和内存释放。

```c
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 确定性 RNG：每次运行看到相同的密钥和随机数。 */
static uint64_t s = 0x243f6a8885a308d3ULL;
static void fixed_rng(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        out[i] = (uint8_t)s;
    }
}

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Test 7：Decaps(sk, Maul(c))。布局：guard || c || guard。 */
static int test_decaps_ct(const char *name) {
    OQS_KEM *kem = OQS_KEM_new(name);
    if (kem == NULL) return -1;
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    uint8_t *pk = malloc(kem->length_public_key), *sk = malloc(kem->length_secret_key);
    uint8_t *buf = malloc(clen + 2), *ss = malloc(sslen);
    uint8_t *ss0 = malloc(sslen), *ss1 = malloc(sslen);

    OQS_KEM_keypair(kem, pk, sk);
    buf[0] = buf[clen + 1] = 0xFF;
    OQS_KEM_encaps(kem, buf + 1, ss, pk);
    OQS_STATUS rv0 = OQS_KEM_decaps(kem, ss0, buf + 1, sk);

    int bad = 0;
    for (size_t bit = 0; bit < 8 * (clen + 2); bit++) {
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* DIFF 区域 */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {  /* DIFF 却相同，或 EQ 却不同 */
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "malleable ciphertext" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

/* Test 13：Verify(pk, m, Maul(sigma))，包括长度。 */
static int test_verify_sig(const char *name) {
    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) return -1;
    size_t cap = sig->length_signature + 16, siglen;
    uint8_t *pk = malloc(sig->length_public_key), *sk = malloc(sig->length_secret_key);
    uint8_t *buf = calloc(cap + 2, 1), msg[32];
    memset(msg, 42, sizeof msg);

    OQS_SIG_keypair(sig, pk, sk);
    buf[0] = buf[cap + 1] = 0xFF;
    OQS_SIG_sign(sig, buf + 1, &siglen, msg, sizeof msg, sk);

    int bad = 0;
    for (size_t len = 0; len <= cap; len++)  /* 任何其他长度都必须失败 */
        if (len != siglen &&
            OQS_SIG_verify(sig, msg, sizeof msg, buf + 1, len, pk) == OQS_SUCCESS) {
            printf("%s: accepts length %zu (true length %zu)\n", name, len, siglen);
            bad++;
        }
    for (size_t bit = 8; bit < 8 * (siglen + 1); bit++) {  /* 签名的每一位 */
        flip(buf, bit);
        if (OQS_SIG_verify(sig, msg, sizeof msg, buf + 1, siglen, pk) == OQS_SUCCESS) {
            printf("%s: bit %zu: malleable signature\n", name, bit - 8);
            bad++;
        }
        flip(buf, bit);
    }
    OQS_SIG_free(sig);
    return bad;
}

int main(int argc, char **argv) {
    OQS_init();
    OQS_randombytes_custom_algorithm(fixed_rng);
    if (argc == 3 && strcmp(argv[1], "kem") == 0) return test_decaps_ct(argv[2]) != 0;
    if (argc == 3 && strcmp(argv[1], "sig") == 0) return test_verify_sig(argv[2]) != 0;
    fprintf(stderr, "usage: %s kem|sig ALGORITHM\n", argv[0]);
    return 2;
}
```

关于这份草稿：

- Test 7 的循环也会翻转两个守卫字节（`EQ` 区域），所以同时检查了越界读。
- 对不声称强不可伪造的方案，Test 13 的命中是信息，不一定是 bug。
- 在 `OQS_KEM_decaps` 周围加上 Valgrind 秘密标记，同一个循环就变成了拒绝路径的恒定时间测试（12.3 节）。
- 要测试非 liboqs 的实现，替换四个 API 调用即可。循环结构就是方法的全部。

## 15. 自查清单

每一条都对应论文中的一个发现。这些条目是对前文 [NGCC 提交前自查清单](../pqc-implementation-guide/?lang=zh) 中 B（KEM / FO）、C（签名）、E（API 与内存）三部分的补充。

**编码**

- [ ] 每个非字节对齐的打包，解码时拒绝非零填充位（NTRU、SNOVA）
- [ ] 每个值只有一种被接受的编码；拒绝“−0”等别名（Falcon）
- [ ] 解码 → 重编码逐字节相等，否则拒绝输入

**长度与缓冲区**

- [ ] 每个长度参数都被使用并检查；错误的签名或密文长度会被拒绝（CROSS）
- [ ] 输出不依赖输入缓冲区之外的字节；在每个分组边界附近的长度上用守卫字节测试（KNOT-384）

**KEM**

- [ ] 翻转任何密文比特都得到不同的密钥，或一个与秘密无关的错误（Test 7）
- [ ] 解封装篡改密文时绝不崩溃或 hang（Big Quake、LEDAkem、LIMA）
- [ ] 如果解封装跳过了重加密，就证明编码在字节层面是单射（NTRU）
- [ ] 文档说明私钥中哪些部分在合法密文上不被使用（FO 的 `z`）

**签名**

- [ ] 若方案声称或蕴含 sUF-CMA，翻转任何签名比特或改变长度都会使验证失败（Test 13）
- [ ] 篡改后的公钥不能验证已有签名（Test 11）
- [ ] 文档说明随机化签名是否用到了全部私钥（Dilithium 的 `K`）

**随机性与鲁棒性**

- [ ] 常量随机带会导致报错或有上限的重试，绝不无限循环（Test 2、5、10）
- [ ] 每个测试都把返回值纳入比较；失败路径返回错误并清空输出

**流程**

- [ ] Test 7 和 Test 13 在每个后端（ref、AVX2、AVX-512、嵌入式）上进入 CI，输出与返回码完全一致
- [ ] 每一种 API 封装（NIST、PQClean、liboqs）都有自己的负向测试

## 来源

- Fenzi, Gilcher, Virdia，“Finding Bugs and Features Using Cryptographically-Informed Functional Testing”，[TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447)；[ePrint 2024/1122](https://eprint.iacr.org/2024/1122)；[代码与复现说明](https://github.com/jangilcher/cryptoTesting) \[source\]
- Mouha, Raunak, Kuhn, Kacker，“Finding Bugs in Cryptographic Hash Function Implementations”，[IEEE Transactions on Reliability 67(3), 2018](https://doi.org/10.1109/TR.2018.2847247)
- Weyuker，“On Testing Non-Testable Programs”，[The Computer Journal 25(4), 1982](https://doi.org/10.1093/comjnl/25.4.465)
- Chen, Cheung, Yiu，“Metamorphic Testing: A New Approach for Generating Next Test Cases”，[arXiv:2002.12543](https://arxiv.org/abs/2002.12543)（1998 年技术报告）
- Chen, Tse, Zhou，“Fault-Based Testing Without the Need of Oracles”，[Information and Software Technology 45(1), 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)
- Fioraldi, Maier, Eißfeldt, Heuse，“AFL++: Combining Incremental Steps of Fuzzing Research”，[USENIX WOOT 2020](https://www.usenix.org/conference/woot20/presentation/fioraldi)
- Gentry, Peikert, Vaikuntanathan，“Trapdoors for Hard Lattices and New Cryptographic Constructions”，STOC 2008，[ePrint 2007/432](https://eprint.iacr.org/2007/432)
- Fujisaki, Okamoto，“Secure Integration of Asymmetric and Symmetric Encryption Schemes”，[CRYPTO 1999](https://doi.org/10.1007/3-540-48405-1_34)
- Hofheinz, Hövelmanns, Kiltz，“A Modular Analysis of the Fujisaki-Okamoto Transformation”，TCC 2017，[ePrint 2017/604](https://eprint.iacr.org/2017/604)
- Pornin, Stern，“Digital Signatures Do Not Guarantee Exclusive Ownership”，[ACNS 2005](https://doi.org/10.1007/11496137_10)
- Reparaz, Balasch, Verbauwhede，“Dude, is my code constant time?”，DATE 2017，[ePrint 2016/1123](https://eprint.iacr.org/2016/1123)
- [NTRU 修复：“Ensure trailing bits of ciphertext are 0”](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) \[source\]
- [liboqs issue #1315：Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315) \[source\]
- [CROSS-lib-oqs issue #1：Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) \[source\]
- [SUPERCOP 关于 KNOT-384 的报告（存档）](https://web.archive.org/web/20200810000404/https:/bench.cr.yp.to/web-impl/amd64-pmnod003-crypto_hash-knot384.html)
- Cremers, Düzlü, Fiedler, Fischlin, Janson，“BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures”，IEEE S&P 2021，[ePrint 2020/1525](https://eprint.iacr.org/2020/1525)
- Brendel, Cremers, Jackson, Zhao，“The Provable Security of Ed25519: Theory and Practice”，IEEE S&P 2021，[ePrint 2020/823](https://eprint.iacr.org/2020/823)
- Jackson, Cremers, Cohn-Gordon, Sasse，“Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures”，ACM CCS 2019，[ePrint 2019/779](https://eprint.iacr.org/2019/779)
- Kannwischer, Schwabe, Stebila, Wiggers，“Improving Software Quality in Cryptography Standardization Projects”，[ePrint 2022/337](https://eprint.iacr.org/2022/337)
- [KpqC 首轮实现安全分析，ePrint 2023/1437](https://eprint.iacr.org/2023/1437)
- [FIPS 203（ML-KEM）](https://csrc.nist.gov/pubs/fips/203/final) 与 [FIPS 204（ML-DSA）](https://csrc.nist.gov/pubs/fips/204/final)
