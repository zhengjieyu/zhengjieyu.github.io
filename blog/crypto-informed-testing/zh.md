# 翻转一个比特：密码学感知测试在 PQC 实现里找到了什么

*面向编写或测试密码代码的读者 · 约 25 分钟阅读 · 2026 年 10 月 21 日*

先看一个真实的 bug。2020 年，LibOQS（一个常用的后量子密码 C 库）里的 NTRU 密钥封装代码，密文最后一个字节有 4 个没用到的比特，代码直接忽略了它们。于是，改动其中任何一位，改动后的密文仍然能解出原来的密钥。这段代码通过了所有已知答案测试，也从来没有崩溃过。但就因为这一个细节，方案声称的安全性质已经不成立了。

这篇文章介绍一种能自动找到这类 bug 的简单方法。方法来自 Giacomo Fenzi、Jan Gilcher、Fernando Virdia 发表在 TCHES 2026 的论文（[论文](https://doi.org/10.46586/tches.v2026.i1.425-447)、[ePrint 2024/1122](https://eprint.iacr.org/2024/1122)、[代码](https://github.com/jangilcher/cryptoTesting)）。我先讲思路，再讲它找到的 bug，最后讲怎么用在自己的代码上。

> **一句话理解：** 取一个合法输入，翻转一个比特，检查输出在应该变的时候变了、在不该变的时候没变。

## 0. 本文内容

读这篇文章不需要先读论文，只需要知道密钥封装机制（KEM）和数字签名是做什么的。其他术语在第一次出现时都会解释。

主要结论：

1. **最重要的安全 bug 不会让程序崩溃。** 普通 fuzzer 只找崩溃，在较新的 LibOQS 版本上什么也没找到；论文的测试找到了几十处安全性质被破坏的情况。
2. **大部分真实 bug 都和编码有关。** 同一个值可以写成不止一种字节串，而代码全都接受。NTRU、Falcon、SNOVA、CROSS 都有这类问题。
3. **方法成本很低。** 它就是套在被测函数外面的一个小循环。对一个库版本完整跑一遍，在服务器上大约需要半天。
4. **不是每个发现都是 bug。** 有些意外结果来自方案本身的设计。论文把它们和真正的 bug 分开讨论，本文也一样。
5. **这个思路可以比论文走得更远。** 第 9 节补充了八项同类检查，每一项都基于中国 NGCC 竞赛公开评审中已公布、而论文的测试会漏掉的 bug。

本文是之前[《PQC 方案实现工程教程》](../pqc-implementation-guide/?lang=zh)的后续。那篇文章（第 7.1 节）列出了 PQC 实现需要的 11 类测试，本文详细介绍其中一类：变形测试。

说明：标注 \[source\] 的链接在写作时核对过。以“*我的看法*”开头的段落是我自己的理解，不是论文的结论。

## 1. 为什么常规测试发现不了这类 bug

密码代码通常用三种方式测试：

| 测试方式 | 做什么 | 为什么没发现 NTRU 的 bug |
| --- | --- | --- |
| 已知答案测试（KAT） | 在一组固定输入上运行代码，把输出和事先存好的正确输出比较 | 测试输入都是合法密文，没有哪个改过填充位 |
| Sanitizer（如 AddressSanitizer） | 程序读写不属于自己的内存时立即报错 | 代码只读了自己的内存，只是忽略了几个比特 |
| Fuzzing（如 [AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi)） | 用大量随机输入运行代码，记录崩溃 | 没有崩溃，错误的结果看起来和正常结果一样 |

根本原因是：密码算法的输出被设计成看起来随机。测试看到一个密钥 `3f a1 9c ...`，没法判断它对不对。软件测试把这叫做**测试预言机问题**（oracle problem，[Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)）。这里的“预言机”指任何能判断输出是否正确的方法。

所以问题变成：单个输出对不对都无法判断，代码还怎么测？

## 2. 思路：比较两个输出，而不是判断一个输出

单个输出对不对，往往没法判断；但两个输出之间应该是什么关系，往往是知道的。这种测试方法叫做**变形测试**（metamorphic testing，[Chen、Cheung、Yiu，1998](https://arxiv.org/abs/2002.12543)；[Chen、Tse、Zhou，2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)）。

哈希函数是最简单的例子。你不知道 `H(x)` 应该等于多少，但你知道两条规则：

- **规则一：每个输入比特都必须起作用。** 翻转消息的任何一位，哈希值都必须改变。如果没变，说明代码忽略了这一位。
- **规则二：输入以外的字节不能起作用。** 改动内存中紧跟在消息后面的一个字节，哈希值必须不变。如果变了，说明代码读到了输入末尾之外。

每条规则都对应一个不需要知道正确答案的测试：翻转一位，重新计算，然后比较。

这个思路用在哈希函数上并不新。2018 年，[Mouha、Raunak、Kuhn、Kacker](https://doi.org/10.1109/TR.2018.2847247) 用这两条规则检查了 SHA-3 竞赛的 86 个参考实现：19 个违反规则一，17 个违反规则二，五个 SHA-3 决赛算法中有两个存在这类 bug。

这篇新论文把同样的思路用到了 KEM 和数字签名上。

### 2.1 守卫字节

为了检查规则二，测试在输入前后各多放一个字节，叫做**守卫字节**。被测函数拿到的是指向真正输入的指针，本不应该读到守卫字节。如果翻转守卫字节导致输出改变，说明函数读到了输入之外。

![Test 7 的缓冲区布局：一个守卫字节、标为 DIFF 的密文（包括最后一个字节的填充位）、一个尾部守卫字节；翻转守卫字节输出必须不变，翻转任何密文比特输出必须改变](./diagrams/buffer-layout.svg)

图中是 KEM 密文的布局。密文的每一位，包括填充位，都标为“必须改变输出”（DIFF）；守卫字节标为“不得改变输出”（EQ）。NTRU 的 bug 就是图中橙色的部分：翻转填充位后，密钥没有变。

*我的看法：* 守卫字节能发现 sanitizer 发现不了的问题。sanitizer 只在代码访问未分配的内存时报错；读到一个更大的合法缓冲区里的下一个字节，在它看来完全正常。

## 3. 把安全定义变成简单的检查

安全定义听起来很抽象，但每一个都能落到一条很具体的检查上。

**IND-CCA（KEM）。** 这是 KEM 的标准安全目标。通俗地说：攻击者可以让系统解封装除目标密文以外的任何密文，但仍然得不到目标密文里密钥的任何信息。

现在假设翻转密文的一位后，解出的还是同一个密钥。攻击者拿到目标密文，翻转一位，让系统解封装这个新密文。这是允许的，因为它和目标密文不同。系统返回了密钥，攻击者就得到了目标密钥。安全性被完全打破。

所以检查是：**翻转合法密文的任何一位再解封装，得到的密钥必须不同。**

**强不可伪造（sUF-CMA，签名）。** 签名通常的目标是：任何人都不能为一条*新*消息伪造签名。强不可伪造要求更多：对已经签过的消息，也不能给出*另一个不同的签名*。有些协议依赖这一点，比如把签名当作交易的唯一编号。

所以检查是：**翻转合法签名的任何一位（或改变签名长度），验证必须失败。**

不是所有方案都声称强不可伪造，NIST 也没有要求。方案没有声称时，检查失败是有用的信息，但不算 bug。

**第二原像抵抗（哈希）。** 很难找到另一条消息具有相同的哈希值。对应的检查就是第 2 节的规则一：翻转一位，哈希值必须改变。

| 安全目标 | 检查 | 检查失败意味着 |
| --- | --- | --- |
| IND-CCA（KEM） | 翻转密文一位再解封装，密钥必须改变 | 方案被打破：攻击者能得到密钥 |
| sUF-CMA（签名） | 翻转签名一位或改变长度，验证必须失败 | 签名可塑。若方案声称 sUF-CMA，则是 bug |
| 第二原像（哈希） | 翻转消息一位，哈希必须改变 | 实现忽略了部分输入 |

## 4. 测试程序怎么工作

测试程序每次都按相同的步骤进行：

1. **构造一个合法输入。** 例如生成密钥对和一个合法密文。
2. **计算正常输出。** 例如解封装这个密文，保存得到的密钥。
3. **改动输入的一个比特。**
4. **重新计算输出。**
5. **比较。** 根据改动的位置，输出要么必须改变，要么必须不变。结果不对时，程序故意崩溃。

第 3 到 5 步对输入的每一位重复一次。程序故意崩溃，是为了让 AFL++ 这样的 fuzzer 记录下出问题的输入。这里用 AFL++ 只是为了并行跑大量测试并保存失败的输入。

![测试循环：GenInput 生成基准输出，Maul 翻转一个比特并给出期望，Call 重新调用函数，Match 不符时 abort，AFL++ 保存触发崩溃的输入](./diagrams/test-loop.svg)

论文把这四部分分别叫做 `GenInput`（第 1、2 步）、`Maul`（第 3 步，maul 意为“损坏”）、`Call`（第 4 步）和 `Match`（第 5 步）。只有 `Call` 与被测方案有关，其他部分写一次，就能用于所有方案和所有库。

在逐位翻转之前，测试还会先试三种简单情况：输入不变（输出必须相同）、输入全部置 0、输入全部置 1。

### 4.1 两个细节

**随机数。** 密钥生成、封装和签名都要用随机字节。为了让测试可以重复，测试把随机字节固定下来。论文还测试了一个“坏掉的”随机数生成器，它一直返回同一个字节。有些实现因此陷入死循环，比如密钥生成一直拒绝候选值、永远结束不了。这不是安全漏洞，但也是 bug。

**长度。** 有些签名长度可变，长度作为一个单独的数字传入。测试也会改动这个数字。第 6.5 节的 CROSS bug 就是这样发现的。

### 4.2 十三个测试

论文把这个循环应用到每个函数的每个输入上：

| 测试 | 函数 | 改动什么 | 必须满足 |
| --- | --- | --- | --- |
| 1 | 哈希 | 消息 | 哈希改变；守卫字节不起作用 |
| 2 | KEM / 签名的密钥生成 | 随机字节 | 密钥改变；不能死循环 |
| 3 | KEM 封装 | 公钥 | 输出改变 |
| 4 | KEM 封装，再用原私钥解封装 | 公钥 | 两个密钥不同 |
| 5 | KEM 封装 | 随机字节 | 输出改变 |
| 6 | KEM 解封装 | 私钥 | 密钥改变 |
| 7 | KEM 解封装 | 密文 | 密钥改变（**IND-CCA**） |
| 8 | 签名 | 私钥 | 签名改变 |
| 9 | 签名 | 消息 | 签名改变 |
| 10 | 签名 | 随机字节 | 签名改变（确定性方案除外） |
| 11 | 验证 | 公钥 | 验证失败 |
| 12 | 验证 | 消息 | 验证失败 |
| 13 | 验证 | 签名及其长度 | 验证失败（**sUF-CMA**） |

最重要的是 Test 7 和 Test 13，它们直接检查两个主要的安全目标。

## 5. 测试找到了什么

作者测试了四个 LibOQS 版本（2018、2020、2023、2025 年），以及 SUPERCOP（一个收录大量实现的基准测试套件）中的哈希函数。专门测老版本，是因为 LibOQS 会删除在 NIST 竞赛中被淘汰的方案，老版本里还保留着它们。

作为对照，作者还在同样的代码上跑了普通 fuzzer，它只找崩溃。

| 库版本 | 普通 fuzzer 找到 | 论文的测试额外找到 |
| --- | --- | --- |
| LibOQS 2018（`nist-branch`） | 27 次崩溃，1 次卡死 | 3 个 IND-CCA 失效 |
| LibOQS 0.4.0（2020） | 17 次崩溃，1 次卡死 | 10 个 IND-CCA 失效、9 个 sUF-CMA 失效、3 个缓冲区溢出 |
| LibOQS 0.8.0（2023） | 无 | 2 个 sUF-CMA 失效 |
| LibOQS 0.14.0（2025） | 无 | 25 个 sUF-CMA 失效 |

合计，论文的测试找到了普通 fuzzer 看不到的 13 个 IND-CCA 失效和 36 个 sUF-CMA 失效，普通 fuzzer 找到的崩溃也几乎都找到了。例外是 Dilithium III 和 Picnic_L3_UR 的两个崩溃：普通 fuzzer 找到了，论文的测试漏掉了。

关于这些数字，有两点要注意：

- 论文按（方案、参数集、库版本）分别计数。一个 bug 影响两个参数集、两个版本，就算四次。所以这些数字不是独立 bug 的个数。
- 不是每个结果都是 bug。有些方案本来就不声称 sUF-CMA，有些结果来自方案设计（第 7 节）。

每个库版本完整跑一遍，在 31 到 75 核的服务器上大约需要半天。完整表格见附录 A。

## 6. 真实的 bug

下面每个案例都按同样的顺序说明：发生了什么，原因是什么，怎么避免。

### 6.1 NTRU：密文里没用到的比特

**发生了什么。** 在 LibOQS 0.4.0 中，NTRU 的三个参数集（HRSS-701、HPS-2048-677、HPS-2048-509）接受翻转了一位的密文，并返回原来的密钥。Test 7 发现了它。这打破了 IND-CCA。

**原因。** 密文存的是一串 11 位或 13 位的数，总位数不是 8 的倍数，所以最后一个字节有 4 位没用到：

| 参数集 | 数据位数 | 字节数 | 最后一个字节中未用的位 |
| --- | --- | --- | --- |
| HPS-2048-509 | 508 × 11 = 5588 | 699 | 4 |
| HPS-2048-677 | 676 × 11 = 7436 | 930 | 4 |
| HRSS-701 | 700 × 13 = 9100 | 1138 | 4 |

规范规定这些位为 0，但解封装从来没有检查。[修复](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) \[source\] 加了一行检查：只要这些位中有 1，就拒绝这个密文。

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

*我的看法：* 很多 KEM 在解封装时会重新加密，再把结果和收到的密文逐字节比较，这一步本可以发现这个 bug。NTRU 不重新加密，它在解密时直接检查解码后的数，而未用的位在解码时就被丢掉了，所以没有任何检查看到它们。

**怎么避免。** 只要数据没有填满最后一个字节，解码时就检查未用的位是否为 0。

### 6.2 KNOT-384：读到消息末尾之外

**发生了什么。** KNOT-384 是 NIST 轻量级密码竞赛中的一个哈希函数。在它的优化代码里，当消息长度是 6 字节的倍数时，哈希值会受到内存中紧跟在消息*后面*那个字节的影响。Test 1 的守卫字节发现了它。

**原因。** 在两种比特顺序之间转换的函数里，掩码写错了。

**怎么避免。** 用守卫字节在多种输入长度上测试。sanitizer 发现不了这类问题。

### 6.3 acehash 和 syconhash：被忽略的输入位

SUPERCOP 中三个向量化（SIMD）哈希实现，`acehash256v1`（SSE2）和 `syconhash256v1`（AVX、SSE），对只差一位的两条消息有时给出相同的哈希值。这是这几个实现的问题，不是算法设计的问题。

*我的看法：* 在随机输入上把优化实现和参考实现做比较，很可能发现不了这个问题，因为随机输入恰好只在被忽略的那一位上不同的概率很低。逐位翻转则每次都能发现。

### 6.4 Falcon：零有两种写法

**发生了什么。** LibOQS 0.4.0 中的 Falcon 签名是可塑的：改动后的签名仍能通过验证。Test 13 发现了它。作者测试时，LibOQS 0.14.0 中仍然存在同样的问题。

**原因。** Falcon 把签名中的每个数存成一个符号位加上数的大小。解码器把“负零”（符号位为 1、大小为 0）也当作合法的 0，而且不检查末尾的填充是否为 0。于是同一个签名可以有多种写法（[liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315) \[source\]）。

**为什么重要。** Falcon 基于 [GPV 框架](https://eprint.iacr.org/2007/432)，这个框架通常能提供强不可伪造，用户会默认 Falcon 也有这个性质。Falcon 团队在规范 1.2 版中修复了这个问题。

**怎么避免。** 每个值只接受一种编码。拒绝“−0”和非零填充。

### 6.5 SNOVA 和 CROSS：未用的位和被忽略的长度

- **SNOVA**（一个较新的签名候选）：部分参数集的签名最后一个字节有未用的位，这些位取任何值都会被接受。和 NTRU 是同一个问题。
- **CROSS**（另一个签名候选）：验证函数收到了签名长度，却没有使用它。所以在合法签名末尾追加任意字节，仍然能通过验证（[issue](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) \[source\]）。这个问题只出现在为 PQClean API 编写的版本中（PQClean 是一个收录可移植 PQC 代码的项目），提交给 NIST 的版本没有问题。

**怎么避免。** 检查每一个长度参数。签名长度不完全正确就拒绝。

### 6.6 崩溃本身就是泄露

在 2018 年的 LibOQS 版本中，三个 KEM（Big Quake、LEDAkem、LIMA）在收到改动过的密文时会崩溃或卡死。崩溃是攻击者能看到的，它告诉攻击者“这个密文不合法”。针对 KEM 的攻击恰好可以利用这种“是/否”的回答，一次查询一点点地恢复私钥。

### 6.7 不算 bug：本来就不声称 IND-CCA 的方案

Test 7 在一些本来就不提供 IND-CCA 的变体上也会失败，例如 ThreeBears 和 SIKE 的临时密钥（ephemeral）版本。这是设计如此，测试套件应当允许把它们标记为预期结果。

## 7. 出人意料，但不是 bug

有些结果不是代码写错了，而是方案设计本身导致的。它们不违反正式的安全目标，但可能让在方案之上搭建系统的人感到意外。

### 7.1 KEM 私钥的一部分在合法密文上用不到

大多数后量子 KEM，包括 ML-KEM，都用 [Fujisaki–Okamoto（FO）变换](https://doi.org/10.1007/3-540-48405-1_34)来达到 IND-CCA 安全。在常见的“隐式拒绝”形式中（[Hofheinz、Hövelmanns、Kiltz](https://eprint.iacr.org/2017/604)），私钥里有一个随机值 `z`。它只在密文不合法时使用：这时 KEM 不报错，而是返回一个由 `z` 生成的假密钥。

![FO 隐式拒绝：合法密文的输出密钥来自 G(m' || h)，拒绝密钥 J(z || c) 虽被计算却被丢弃，因此修改 z 不改变输出](./diagrams/fo-implicit-rejection.svg)

对合法密文，假密钥也会被计算（让两种情况的运行时间相同），然后丢弃。所以改动 `z` 后，解封装合法密文仍然得到正确的密钥。这就是为什么即使 KEM 实现正确，Test 6 也会报告很多结果。

**什么时候会有影响。** 假设一个系统用“解封装一个合法密文”来检查存储的私钥是否完好。`z` 损坏的私钥也能通过这个检查，问题要等到收到不合法密文时才会暴露。

### 7.2 随机化 Dilithium 忽略了私钥的一部分

Dilithium 的私钥里有一个 256 位的值 `K`。确定性版本用 `K` 生成签名用的随机数；随机化版本改用新的随机字节，不使用 `K`。两个版本的私钥格式相同。所以在随机化版本中，只在 `K` 上不同的两个私钥，在随机字节相同时会给出相同的签名（Test 8）。只有随机数生成器坏掉时，才会注意到这一点。

*我的看法：* 标准化后的 ML-DSA（FIPS 204）总是把 `K` 和新的随机字节混在一起使用，所以不再有这个问题。

### 7.3 可以被改动的公钥

在 LibOQS 0.4.0 中，部分 Rainbow 和 Falcon 的公钥可以被改动，而已有的签名在改动后的公钥下仍能通过验证（Test 11）。这个问题后来已经修复。攻击者得不到改动后公钥对应的私钥，所以无法签新消息。但如果一个协议假设“一个签名只属于一个公钥”，就可能出错。这种性质叫做排他所有权（exclusive ownership，[Pornin、Stern，2005](https://doi.org/10.1007/11496137_10)；[Cremers 等，2021](https://eprint.iacr.org/2020/1525)）。[Jackson 等](https://eprint.iacr.org/2019/779)的工作表明，这类性质确实会导致真实协议出问题。

## 8. 方法的局限

- **一次只翻转一位。** 有些 bug 需要同时改两处，或需要某个特定的值（比如一个恰好等于模数 `q` 的数），单比特翻转触发不了。
- **只从一个输入出发。** 每个测试只用一个固定的密钥和一条固定的消息，只在特殊密钥上出现的 bug 可能被漏掉。这也是普通 fuzzer 找到了两个这些测试漏掉的崩溃的原因。
- **不检查代码是否符合规范。** 这需要一个独立的规范模型，并比较中间值。
- **数字不是 bug 个数。** 其中包括重复计数和预期结果（第 5 节）。

所以这个方法不能取代普通 fuzzing，它补上的是普通 fuzzing 做不到的那一类检查。第 9 节介绍如何补上其中一部分空白。

## 9. 更进一步：更多可以测试的关系

论文只用了一种关系：改动输入后的输出，要么必须和原输出相同，要么必须不同。按照同样的原则，还可以写出很多关系。仍然不需要知道正确输出是什么，只需要把输出互相比较。

为了找出值得补充的关系，我看了 [ngcc.dev](https://ngcc.dev/) 上已公开的中国 NGCC 竞赛首轮发现。这是 Markku-Juhani Saarinen 维护的公开评审网站，截至 2026 年 10 月共有 413 条发现。其中有不少 bug 和论文测的是同一类，但论文的测试发现不了。下面每一小节说明一个这样的空白、一个属于这个空白的已公开 bug，以及能发现它的检查。发现编号链接到完整报告。

### 9.1 把改动后的输出互相比较，而不只是和原输出比较

**空白。** Test 7 只检查改动后的密文得到的密钥*和真实密钥不同*。但在隐式拒绝的 KEM 中，不合法密文得到的密钥还必须看起来是随机的。和真实密钥不同的密钥，仍然可能是错的。

**已公开的 bug。**

- **CheetahKEM**（[kem-09-1](https://ngcc.dev/reports/kem-09.html)）和 **LoongKEM**（[kem-18-1](https://ngcc.dev/reports/kem-18.html)）：在真实密钥和拒绝密钥之间做选择的代码用错了掩码。对不合法的密文，它返回两者的混合，真实密钥的大部分比特因此泄露。返回的密钥和真实密钥不同，所以 Test 7 会通过。
- **BAG-Loong**（[kem-03-2](https://ngcc.dev/reports/kem-03.html)）、**CheetahKEM**（[kem-09-4](https://ngcc.dev/reports/kem-09.html)）和 **DKEM**（[kem-13-1](https://ngcc.dev/reports/kem-13.html)，由我报告）：拒绝密钥只用到了收到的密文的一部分，或者用的是重新加密得到的密文，而不是收到的密文。于是不同的不合法密文可能得到同一个拒绝密钥。它们都和真实密钥不同，所以 Test 7 会通过。在 CheetahKEM 中，仅凭解封装查询就能据此恢复私钥。

**检查。** 收集所有改动后的密文得到的密钥，检查两条规则：

1. **任意两个改动后的密文得到的密钥都不相同。** 出现相同说明拒绝密钥忽略了密文的一部分。
2. **任何拒绝密钥都不像真实密钥。** 两个无关的 256 位密钥大约有一半的位相同。如果某个拒绝密钥和真实密钥相同的位远多于一半，说明真实密钥的一部分正在泄露。

这和 Mouha 等人最初对哈希函数的做法接近：他们收集所有输出，寻找任何一对相同的输出。论文为了适配 AFL++ 的工作方式，改为每个输出只和原输出比较，也就失去了这个能力。

### 9.2 返回码不能取决于密文是否合法

**空白。** 论文把返回码算作输出的一部分。对改动后的密文，输出本来就应该改变，所以返回码变了，测试照样通过。

**已公开的 bug。** **DTRU**（[kem-14-2](https://ngcc.dev/reports/kem-14.html)）：解封装走隐式拒绝分支时，返回码和正常时不同。这会告诉攻击者密文是否合法，而隐式拒绝要隐藏的正是这一点。

**检查。** 对声称使用隐式拒绝的 KEM，每个改动后的密文的返回码都必须和合法密文的相同。对使用显式拒绝的 KEM，文档必须说明这一点。

### 9.3 改数值，而不只是改比特

**空白。** 很多编码把数存成模 `q`（或模素数 `p`）的值。如果解码器把 `x + q` 也当作 `x` 的一种写法，同一个值就有两种字节串。翻转一位只会让数值变化 2 的幂，永远不会恰好变化 `q`，所以单比特翻转发现不了这个问题。

**已公开的 bug。** **QIMEN-PIKE**（[kem-31-2](https://ngcc.dev/reports/kem-31.html)）：解码器把域元素模 `p` 约简，却不拒绝大于等于 `p` 的值，于是密文可以被改动而密钥不变。这打破了 IND-CCA。**TSUOV**（[sign-31-6](https://ngcc.dev/reports/sign-31.html)）没有拒绝一个未使用的域元素取值；**YuanYang.DSA**（[sign-34-2](https://ngcc.dev/reports/sign-34.html)）的公钥存在不止一种编码。

**检查。** 把输入描述成一组字段（每个字段：位宽和允许的取值范围），而不只是一串比特。对每个字段，试 `q`、`q + 1`、能放下的最大值，以及 `x + q`。解码要么拒绝输入，要么得到不同的输出。更简单也更强的做法是：解码后重新编码，要求得到相同的字节。

### 9.4 每一个长度都改，往两个方向改

**空白。** 论文只改签名长度，而且只往短里改。但很多 API 中，KEM 函数和密钥输入也带长度参数。

**已公开的 bug。** **DTRU**（[kem-14-1](https://ngcc.dev/reports/kem-14.html)）：调用者声明的密文长度可以让解封装中的栈缓冲区溢出。**Rudraksh2**（[kem-34-3](https://ngcc.dev/reports/kem-34.html)）：KEM 函数不看声明的长度，会读到过短缓冲区之外。**Tins**（[sign-29-3](https://ngcc.dev/reports/sign-29.html)）：过长的签名长度没有检查，导致验证器中的缓冲区溢出。

**检查。** 对每个长度参数，试 0、正确长度减一、正确长度加一，以及一个大得多的值。每次调用都必须返回错误，而且不能崩溃。这些测试要在 AddressSanitizer 下运行，因为读越界不一定导致崩溃。

### 9.5 按方案结构做的改动

**空白。** 有些改动能保持输入格式合法，只有了解方案才想得到。随机翻转比特几乎不会产生这类改动。

**已公开的 bug。**

- **TRINE**（[sign-30-5](https://ngcc.dev/reports/sign-30.html)）：签名中的每个响应向量都可以换成它自己的任意非零倍数，签名仍能通过验证。
- **VDOO**（[sign-33-7](https://ngcc.dev/reports/sign-33.html)）：在消息和签名存放在一起的 API 格式中，移动两者之间的边界，就得到一条更短或更长的新消息的合法签名。
- **Galas**（[sign-12-2](https://ngcc.dev/reports/sign-12.html)）等：哈希之前，消息长度被截断成 32 位。超过 4 GiB 的消息被当作一条短得多的消息来哈希，从而可以伪造签名。

**检查。** 为每个方案列出能保持格式合法的变换：向量乘以标量、取负、移动边界、超长输入。把每个变换作用到一个合法的签名或密文上。规则和前面一样：改动后的输入不能通过验证，或不能得到相同的密钥。这需要一些方案知识，但每个变换只要几行代码。

### 9.6 跨进程比较，而不只在一个进程内比较

**空白。** 随机数测试（Test 2、5、10）都在一个进程内运行。如果实现不用传给它的随机字节，而是用自己的内部计数器，同一进程中先后生成的密钥仍然各不相同，测试就会通过。

**已公开的 bug。** **HEP-QC**（[kem-17-1](https://ngcc.dev/reports/kem-17.html)）：密钥生成不使用 API 提供的随机数生成器。每个新进程都从相同的内部状态开始，生成同一对密钥，任何人都能算出私钥。ngcc.dev 的测试程序通过比较多个新进程生成的第一个密钥来检查这一点。

**检查。** 用不同的随机种子启动两个新进程，比较它们生成的第一对密钥、第一个密文和第一个签名，必须不同。

### 9.7 实现之间互相比较

**空白。** 论文分别测试每个实现。但一个方案通常有一个参考版本和一个或多个优化版本，bug 可能只出现在其中一个版本里。

**已公开的 bug。** **FLIT**（[kem-15-1](https://ngcc.dev/reports/kem-15.html)）：FLIT512 的参考代码和优化代码在不报错的情况下得出不同的密钥。**FLIT**（[kem-15-2](https://ngcc.dev/reports/kem-15.html)）：只有 AVX2 版本的比较逻辑有错，会接受大多数不合法的密文。**PolarLAC**（[kem-30-3](https://ngcc.dev/reports/kem-30.html)）：一个版本生成的密文，另一个版本无法正确解封装。

**检查。** 给每个版本相同的输入，包括上面各项测试中所有改动过的输入。所有版本必须返回相同的字节和相同的返回码。这完全不需要知道正确输出：各个版本互相检查。

### 9.8 哈希函数：跨长度比较

**空白。** Test 1 只把改动后的消息和同样长度的原消息比较。有些哈希 bug 只出现在不同长度的消息之间。

**已公开的 bug。** **Eijen**（[hash-09-1](https://ngcc.dev/reports/hash-09.html)）：空消息和 7 个零比特组成的消息哈希值相同。**MasterCube**（[hash-17-1](https://ngcc.dev/reports/hash-17.html)）：958 个 1 比特和 959 个 1 比特的消息哈希值相同，而且每个分组边界都会出现这种情况。

**检查。** 对大量不同长度的消息求哈希，特别是长度接近字节边界和分组边界的消息，以及只差末尾几个零比特的消息，寻找任意两个相同的哈希值。这就是 Mouha 等人最初的 bit-contribution 测试，只是用在不同长度之间。

### 9.9 小结

| 检查 | 比论文的测试多发现什么 | 已公开的例子 | 是否需要方案知识 |
| --- | --- | --- | --- |
| 拒绝密钥互相比较、并与真实密钥比较 | 泄露信息或不绑定密文的拒绝密钥 | kem-09-1、kem-13-1 | 否 |
| 返回码与密文是否合法无关 | 拒绝分支泄露 | kem-14-2 | 只需知道是否为隐式拒绝 |
| 改字段数值、重新编码 | `x` 与 `x + q` 的重复编码 | kem-31-2、sign-31-6 | 需要字段位宽和模数 |
| 每个长度，两个方向 | 被忽略或未检查的长度 | kem-14-1、kem-34-3、sign-29-3 | 否 |
| 按结构改动 | 标量倍数、边界移动、超长输入 | sign-30-5、sign-33-7、sign-12-2 | 是 |
| 跨进程比较 | 被忽略的随机数生成器 | kem-17-1 | 否 |
| 实现之间比较 | 只出现在一个版本里的 bug | kem-15-1、kem-15-2、kem-30-3 | 否 |
| 跨长度的哈希碰撞 | 填充和长度 bug | hash-09-1、hash-17-1 | 否 |

八项检查中有五项不需要任何方案知识，可以像论文的测试一样，对竞赛的每个候选自动运行。

下面是第一项检查（9.1 节）的代码，可以加到 10.2 节的 Test 7 程序里。

```c
/* 9.1 节：不同的改动后密文得到的拒绝密钥必须两两不同，
   而且任何一个都不能和真实密钥有过多相同的位。 */
static int check_rejection_keys(OQS_KEM *kem, uint8_t *c, const uint8_t *sk,
                                const uint8_t *real_key) {
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    size_t n = 8 * clen;                     /* 每一位对应一个改动后的密文 */
    uint8_t *keys = malloc(n * sslen);
    int bad = 0;

    for (size_t bit = 0; bit < n; bit++) {
        flip(c, bit);
        OQS_KEM_decaps(kem, keys + bit * sslen, c, sk);
        flip(c, bit);
        size_t same = 0;                     /* 与真实密钥相同的位数 */
        for (size_t i = 0; i < sslen; i++)
            same += 8 - __builtin_popcount(keys[bit * sslen + i] ^ real_key[i]);
        if (4 * same > 3 * 8 * sslen) {      /* 正常情况下约为一半 */
            printf("bit %zu: rejection key shares %zu bits with the real key\n", bit, same);
            bad++;
        }
    }
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (memcmp(keys + i * sslen, keys + j * sslen, sslen) == 0) {
                printf("bits %zu and %zu: same rejection key\n", i, j);
                bad++;
            }
    free(keys);
    return bad;
}
```

## 10. 用在自己的代码上

### 10.1 运行作者的代码

[作者的代码](https://github.com/jangilcher/cryptoTesting) \[source\] 在 Docker 中运行。`bash run.sh` 启动容器，在容器中运行 `bash reproduce.sh ches_liboqs` 可以复现 LibOQS 0.14.0 的实验。0.8.0 用 `cur_liboqs`，0.4.0 用 `mid_liboqs`，2018 版用 `old_liboqs`，哈希函数用 `supercop`。末尾加上 `baseline` 则改为运行普通 fuzzer。

### 10.2 自己写 Test 7 和 Test 13

运行这两个最重要的测试，不需要 AFL++。下面的程序使用 liboqs 的公开 API，为了简洁，省略了错误处理和内存释放。

```c
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 固定的“随机”字节，让每次运行得到相同的密钥。 */
static uint64_t s = 0x243f6a8885a308d3ULL;
static void fixed_rng(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        out[i] = (uint8_t)s;
    }
}

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Test 7：改动密文的一位。布局：guard || c || guard。 */
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
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* 在密文内：密钥必须改变 */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {  /* 密文内却没变，或守卫字节却变了 */
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "malleable ciphertext" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

/* Test 13：先改签名长度，再逐位改签名。 */
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
    for (size_t len = 0; len <= cap; len++)  /* 其他任何长度都必须失败 */
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

几点实用建议：

- 在代码的每个版本上都跑这两个测试：可移植的参考实现，以及每个优化版本（AVX2、AVX-512、嵌入式）。所有版本在每个改动后的输入上，结果都必须一致，返回码也要一致。
- 这两个测试也可以顺便做时序检查：在 Valgrind 下运行 Test 7，把私钥标记为未定义内存，Valgrind 会报告所有依赖私钥的分支。每个改动后的密文都会走拒绝路径，而 FO 的时序泄露通常就出现在这条路径上。如果需要统计意义上的时序检查，可以用 [dudect](https://eprint.iacr.org/2016/1123)。
- 每一种 API 封装（NIST API、PQClean API、liboqs）都是单独的代码，都需要自己的测试。CROSS 的 bug 就只出现在其中一种封装里。

### 10.3 与 NGCC 发现的对应关系

我在[之前的文章](../pqc-implementation-guide/?lang=zh)里，把中国 NGCC 竞赛首轮发现的实现问题分成了 9 类。这些测试能覆盖其中一部分：

| NGCC 类别 | 能否覆盖 | 说明 |
| --- | --- | --- |
| 2. FO 变换实现错误 | 能（Test 6、7） | “只比较每第 4 个字节”（kem-02-1）正是 Test 7 能发现的问题 |
| 4. 输入解析与内存安全 | 能 | 改动输入后的崩溃和溢出；守卫字节还能发现越界读 |
| 5. 编码非单射 | 能（Test 7、11、13） | 即 NTRU、Falcon、SNOVA、CROSS 这类问题 |
| 3. 随机数问题 | 部分（Test 2、5、10） | 能发现坏随机数导致的死循环 |
| 1、6、7、8、9（安全预算、与规范不一致、状态、协议、调试代码） | 否 | 需要其他检查，比如独立的规范模型 |

## 11. 自查清单

每一条都来自上文的真实发现，是对[前文自查清单](../pqc-implementation-guide/?lang=zh)中 B、C、E 三部分的补充。

**编码**

- [ ] 数据没有填满最后一个字节时，解码会拒绝非零的未用位（NTRU、SNOVA）
- [ ] 每个值只接受一种编码；拒绝“−0”之类的重复写法（Falcon）
- [ ] 字段中大于等于 `q` 的值会被拒绝（9.3 节）
- [ ] 解码后再编码，得到的字节与原来相同；否则拒绝输入

**长度与缓冲区**

- [ ] 检查每一个长度参数，长度不对就拒绝（CROSS）
- [ ] 每个长度参数都在 AddressSanitizer 下用 0、少一、多一和一个大得多的值测试过（9.4 节）
- [ ] 输出不依赖输入以外的字节，并用守卫字节在多种长度上测试过（KNOT-384）

**KEM**

- [ ] 翻转密文的任何一位，密钥都会改变，或者返回一个不泄露任何秘密的错误（Test 7）
- [ ] 不同的不合法密文得到不同的拒绝密钥，且没有哪个拒绝密钥和真实密钥有异常多的相同位（9.1 节）
- [ ] 使用隐式拒绝时，合法和不合法密文的返回码相同（9.2 节）
- [ ] 解封装改动后的密文时，绝不崩溃或卡死（Big Quake、LEDAkem、LIMA）
- [ ] 如果解封装没有逐字节比较重新加密的结果，就用别的方式检查编码（NTRU）
- [ ] 文档说明私钥中哪些部分在合法密文上不会被用到（FO 的 `z`）

**签名**

- [ ] 如果方案声称强不可伪造：翻转签名的任何一位或改变长度，验证都会失败（Test 13）
- [ ] 改动后的公钥不能验证已有的签名（Test 11）

**随机数与鲁棒性**

- [ ] 随机数生成器坏掉时，程序报错或只重试有限次，绝不死循环（Test 2、5、10）
- [ ] 用不同随机种子启动的两个新进程，生成的密钥、密文和签名都不同（9.6 节）
- [ ] 测试同时比较返回值和输出字节

**流程**

- [ ] Test 7 和 Test 13 在代码的每个版本（参考实现和优化实现）上进入 CI，结果完全一致（9.7 节）
- [ ] 每一种 API 封装都有自己的负向测试

## 附录 A. 完整结果

各库版本、各测试的结果（论文 Table 3）。“可塑”指应该改变的输出没有改变；“越界读”指不该改变的输出改变了。没有结果的测试不列出。

| 库 | 测试 | 可塑 | 崩溃 / 卡死 | 越界读 |
| --- | --- | --- | --- | --- |
| SUPERCOP 20240107 | 1 | 3 | 0 | 3 |
| LibOQS 0.14.0 | 5 | 1 | 10 次卡死 | 0 |
| | 6 | 26 | 0 | 0 |
| | 8 | 11 | 0 | 0 |
| | 11 | 10 | 0 | 0 |
| | 13 | 25 | 0 | 0 |
| LibOQS 0.8.0 | 3 | 10 | 0 | 0 |
| | 4 | 10 | 0 | 0 |
| | 5 | 1 | 10 次卡死 | 0 |
| | 6 | 23 | 0 | 0 |
| | 8 | 3 | 0 | 0 |
| | 13 | 2 | 0 | 0 |
| LibOQS 0.4.0 | 3 | 23 | 8 次段错误 | 0 |
| | 4 | 31 | 8 次段错误 | 0 |
| | 5 | 1 | 10 次卡死 | 0 |
| | 6 | 51 | 0 | 0 |
| | 7 | 10 | 0 | 0 |
| | 8 | 10 | 3 次堆溢出，1 次卡死 | 0 |
| | 9 | 0 | 1 次卡死 | 0 |
| | 10 | 22 | 1 次卡死 | 0 |
| | 11 | 7 | 1 次卡死 | 0 |
| | 12 | 0 | 1 次卡死 | 0 |
| | 13 | 9 | 1 次卡死 | 0 |
| LibOQS 2018 | 2 | 3 | 0 | 0 |
| | 3 | 4 | 6 次段错误，1 次返回错误 | 0 |
| | 4 | 9 | 7 次段错误，1 次卡死 | 0 |
| | 6 | 24 | 12 次段错误，7 次卡死 | 0 |
| | 7 | 3 | 9 次段错误，2 次栈溢出，4 次卡死 | 0 |
| | 10 | 6 | 0 | 0 |

普通 fuzzer 的崩溃数（括号内为卡死次数）：

| 库 | KEM 封装 | KEM 解封装 | 签名 | 验证 | 耗时 | 核数 |
| --- | --- | --- | --- | --- | --- | --- |
| LibOQS 0.14.0 | 0 | 0 | 0 | 0 | 2h | 31 |
| LibOQS 0.8.0 | 0 | 0 | 0 | 0 | 27m | 50 |
| LibOQS 0.4.0 | 8 | 0 | 9 (1) | 0 | 57m | 50 |
| LibOQS 2018 | 10 | 12 (1) | 5 | — | 23m | 75 |
| SUPERCOP（哈希） | 4 | | | | 8h 6m | 50 |

## 附录 B. 实验细节

- **论文测试的运行时间：** LibOQS 0.14.0 用 75 核 12h 40m；0.8.0 用 31 核 14h 23m；0.4.0 用 31 核 12h 43m；2018 版用 31 核 8h 59m；SUPERCOP 用 31 核 6h 58m。
- **机器：** 2× Intel Xeon Gold 6138（40 核）、4× Intel Xeon Gold 6252（96 核）、1× AMD EPYC 7742（64 核）。
- **AFL++ 设置：** 因为有些公钥很大，输入大小上限从 1 MB 提高到 10 MB；所有内置的输入变异都换成单比特翻转；每个目标最多保存 10 个失败输入。
- **计数方式：** 每个（方案、参数集、库版本）只算一个结果，即使有多个输入触发。

## 来源

- Fenzi, Gilcher, Virdia，“Finding Bugs and Features Using Cryptographically-Informed Functional Testing”，[TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447)；[ePrint 2024/1122](https://eprint.iacr.org/2024/1122)；[代码](https://github.com/jangilcher/cryptoTesting) \[source\]
- Mouha, Raunak, Kuhn, Kacker，“Finding Bugs in Cryptographic Hash Function Implementations”，[IEEE Transactions on Reliability 67(3), 2018](https://doi.org/10.1109/TR.2018.2847247)
- Weyuker，“On Testing Non-Testable Programs”，[The Computer Journal 25(4), 1982](https://doi.org/10.1093/comjnl/25.4.465)
- Chen, Cheung, Yiu，“Metamorphic Testing: A New Approach for Generating Next Test Cases”，[arXiv:2002.12543](https://arxiv.org/abs/2002.12543)（1998 年技术报告）
- Chen, Tse, Zhou，“Fault-Based Testing Without the Need of Oracles”，[Information and Software Technology 45(1), 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)
- Fioraldi, Maier, Eißfeldt, Heuse，“AFL++: Combining Incremental Steps of Fuzzing Research”，[USENIX WOOT 2020](https://www.usenix.org/conference/woot20/presentation/fioraldi)
- Gentry, Peikert, Vaikuntanathan，“Trapdoors for Hard Lattices and New Cryptographic Constructions”，STOC 2008，[ePrint 2007/432](https://eprint.iacr.org/2007/432)
- Fujisaki, Okamoto，“Secure Integration of Asymmetric and Symmetric Encryption Schemes”，[CRYPTO 1999](https://doi.org/10.1007/3-540-48405-1_34)
- Hofheinz, Hövelmanns, Kiltz，“A Modular Analysis of the Fujisaki-Okamoto Transformation”，TCC 2017，[ePrint 2017/604](https://eprint.iacr.org/2017/604)
- Pornin, Stern，“Digital Signatures Do Not Guarantee Exclusive Ownership”，[ACNS 2005](https://doi.org/10.1007/11496137_10)
- Cremers, Düzlü, Fiedler, Fischlin, Janson，“BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures”，IEEE S&P 2021，[ePrint 2020/1525](https://eprint.iacr.org/2020/1525)
- Jackson, Cremers, Cohn-Gordon, Sasse，“Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures”，ACM CCS 2019，[ePrint 2019/779](https://eprint.iacr.org/2019/779)
- Reparaz, Balasch, Verbauwhede，“Dude, is my code constant time?”，DATE 2017，[ePrint 2016/1123](https://eprint.iacr.org/2016/1123)
- [NTRU 修复：“Ensure trailing bits of ciphertext are 0”](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) \[source\]
- [liboqs issue #1315：Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315) \[source\]
- [CROSS-lib-oqs issue #1：Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1) \[source\]
- [ngcc.dev](https://ngcc.dev/)，NGCC 首轮候选的公开评审（第 9 节引用的发现于 2026-10-21 访问）；[复现工具](https://github.com/ngcc-dev/ngcc-harness) \[source\]
- [FIPS 203（ML-KEM）](https://csrc.nist.gov/pubs/fips/203/final) 与 [FIPS 204（ML-DSA）](https://csrc.nist.gov/pubs/fips/204/final)
