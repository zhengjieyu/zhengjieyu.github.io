# 翻转一个比特：不知道正确答案，怎么测试密码代码

*面向编写或测试密码代码的读者 · 约 15 分钟阅读 · 2026 年 10 月 21 日*

2020 年，LibOQS 里的 NTRU 代码有一个小 bug。LibOQS 是一个常用的后量子密码 C 库，NTRU 是它收录的一个密钥封装机制（KEM）。NTRU 密文的最后一个字节里有 4 个比特不存任何数据，解封装代码从来不看它们。所以，你可以翻转其中一位，把改过的密文交给解封装，拿回来的还是原来的共享密钥。

这听起来无关紧要，但它破坏了这个 KEM 最主要的安全承诺。而且没有任何测试发现它：代码通过了已知答案测试，从来没有崩溃过，AddressSanitizer 也没有报告任何问题。

Giacomo Fenzi、Jan Gilcher、Fernando Virdia 在 TCHES 2026 发表的一篇论文（[论文](https://doi.org/10.46586/tches.v2026.i1.425-447)、[代码](https://github.com/jangilcher/cryptoTesting)），介绍了一种能自动发现这类 bug 的简单方法。这篇文章先讲这个方法，再看它找到的几个 bug，最后再往前走一步：借助中国 NGCC 竞赛公开评审中的 bug，看看这个方法会漏掉什么，以及补上哪些检查能发现它们。

> **一句话理解：** 取一个合法输入，翻转一个比特，检查输出在应该变的时候变了、在不该变的时候没变。

## 1. 为什么密码代码很难测试

大多数代码的测试方法，是把输出和一个事先知道的答案比较。对密码代码来说，这件事比想象中难。

最常用的是已知答案测试（KAT）：在一组固定输入上运行代码，把输出和存好的结果比较。但这些结果本身来自参考实现，而参考实现也只是代码。参考实现有 bug，KAT 里就有同样的 bug。而且 KAT 只用合法输入，只在“稍微坏掉的密文”上才出现的 bug，根本测不到。

AddressSanitizer 这类 sanitizer 能发现越界读写，[AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi) 这类 fuzzer 会用大量随机输入运行程序、记录崩溃。它们都很有用。但 NTRU 的 bug 既没有访问不该访问的内存，也没有崩溃，只是返回了错误的结果，而这个错误的结果看起来和正常的密钥没有区别。

更根本的原因是，密码算法的输出被设计成看起来随机。测试看到一个密钥 `3f a1 9c ...`，没有办法判断它对不对。软件测试把这叫做**测试预言机问题**（oracle problem，[Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)）：没有一个“预言机”能告诉你某个输出是否正确。

## 2. 办法：比较两个输出

单个输出对不对，常常没法判断；但两个输出之间应该是什么关系，常常是知道的。这种测试方法叫做**变形测试**（metamorphic testing，[Chen、Cheung、Yiu，1998](https://arxiv.org/abs/2002.12543)；[Chen、Tse、Zhou，2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)）。

以哈希函数为例。你不知道 `H(x)` 应该等于多少，但你知道两件事。第一，消息的每一位都应该起作用：翻转任何一位，哈希值都必须改变。第二，消息以外的东西都不应该起作用：改动内存中紧跟在消息后面的那个字节，哈希值必须不变。

这两条都能直接变成测试，而且不需要知道正确答案：翻转一位，重新计算，然后比较。

这个想法并不新。2018 年，[Mouha、Raunak、Kuhn、Kacker](https://doi.org/10.1109/TR.2018.2847247) 用这两条规则检查了提交给 SHA-3 竞赛的 86 个参考实现。其中 19 个忽略了某个输入比特，17 个读到了消息末尾之外，五个 SHA-3 决赛算法里有两个在其中。

为了检查第二条规则，测试会在输入前后各多放一个字节，叫做**守卫字节**，然后把指向中间真正输入的指针交给被测函数。如果翻转守卫字节改变了输出，说明函数读了它不该读的内存。对 KEM 密文来说，布局是这样的：

![Test 7 的缓冲区布局：一个守卫字节、标为 DIFF 的密文（包括最后一个字节的填充位）、一个尾部守卫字节；翻转守卫字节输出必须不变，翻转任何密文比特输出必须改变](./diagrams/buffer-layout.svg)

密文的每一位，包括填充位，都必须影响输出；守卫字节则不能影响输出。图中橙色的部分就是 NTRU 的 bug。

守卫字节能发现 sanitizer 发现不了的问题。sanitizer 只在代码访问未分配的内存时报错。如果代码读的是一个更大的合法缓冲区里的下一个字节，sanitizer 看不出任何问题。

## 3. 安全定义本身就是测试规则

这篇论文把同样的思路用到了 KEM 和数字签名上。关键在于：它们的安全定义可以直接翻译成能测试的规则。

先看 **IND-CCA**，这是 KEM 的标准安全目标。通俗地说：攻击者可以让系统解封装任何他想要的密文，只有他正在攻击的那一个除外，但即便如此，他仍然得不到那个密文里密钥的任何信息。

现在假设翻转密文的一位，得到的还是同一个密钥。攻击者拿到目标密文，翻转一位，再请求解封装这个新密文。这是允许的，因为它和目标密文不同。系统返回密钥，攻击者就拿到了目标密钥。这就是 NTRU 的 bug，安全性被完全打破。

所以 IND-CCA 给出了一条简单的规则：**翻转合法密文的任何一位再解封装，得到的密钥必须不同。**

签名也是一样。通常的安全目标是：任何人都不能为新消息伪造签名。更强的目标叫**强不可伪造**（sUF-CMA），它还要求：对已经签过的消息，也不能给出另一个不同的签名。有些协议依赖这一点，比如把签名当作唯一编号使用。对应的规则是：**翻转合法签名的任何一位，或者改变它的长度，验证都必须失败。** NIST 没有要求强不可伪造，所以对有些方案来说，这里的失败只是一条信息；但对另一些方案，后面会看到，这是真正的 bug。

## 4. 测试程序做了什么

每个测试都是同样的五步：

1. 构造一个合法输入，比如一对密钥和一个密文。
2. 计算正常输出，比如解封装得到的密钥。
3. 翻转输入的一位。
4. 重新计算输出。
5. 按规则检查输出该变的是否变了、不该变的是否没变。不符合就故意让程序崩溃。

第 3 到 5 步对每一位重复一次。故意崩溃，是为了让 AFL++ 这样的 fuzzer 把出问题的输入保存下来。这里用 AFL++ 只是为了并行运行大量测试、保存失败的输入，它原本的随机变异功能是关掉的。

![测试循环：GenInput 生成基准输出，Maul 翻转一个比特并给出期望，Call 重新调用函数，Match 不符时 abort，AFL++ 保存触发崩溃的输入](./diagrams/test-loop.svg)

在逐位翻转之前，测试还会先试三种情况：输入不变、全部置 0、全部置 1。论文把循环的四个部分叫做 `GenInput`、`Maul`（意为“损坏”）、`Call` 和 `Match`。只有 `Call` 和被测算法有关，所以同一套代码可以用在库里的每个方案上。

论文对每个函数的每个输入都跑这个循环：哈希、密钥生成、封装、解封装、签名和验证，一共 13 个测试。有两个细节值得一提。用到随机字节的函数，测试会把随机字节固定下来，让结果可以重复；同时还会试一个坏掉的随机数生成器，它永远返回同一个字节，有些实现因此陷入死循环。签名长度可变时，测试也会改动长度字段。

最重要的两个测试就是第 3 节说的那两个：解封装之前改密文（Test 7），验证之前改签名（Test 13）。

## 5. 找到了什么

作者在 LibOQS 的四个版本（2018、2020、2023、2025 年）以及 SUPERCOP 的哈希函数上运行了这些测试。SUPERCOP 是一个收录了大量实现的基准测试套件。专门测老版本，是因为 LibOQS 会删掉在 NIST 竞赛中被淘汰的方案，只有老版本里还留着它们。完整跑一遍，在服务器上大约需要半天。

为了看出新测试多发现了什么，作者还在同样的代码上跑了普通 fuzzer：

| LibOQS 版本 | 普通 fuzzer | 新测试额外发现 |
| --- | --- | --- |
| 2018 | 27 次崩溃，1 次卡死 | 3 个 IND-CCA 失效 |
| 0.4.0（2020） | 17 次崩溃，1 次卡死 | 10 个 IND-CCA 失效、9 个 sUF-CMA 失效、3 个缓冲区溢出 |
| 0.8.0（2023） | 无 | 2 个 sUF-CMA 失效 |
| 0.14.0（2025） | 无 | 25 个 sUF-CMA 失效 |

值得注意的是最后两行。在较新的版本上，普通 fuzzer 什么都找不到，新测试仍然找到了几十个问题。普通 fuzzer 找到的崩溃，新测试也几乎都找到了，只有 Dilithium III 和 Picnic_L3_UR 的两个崩溃是普通 fuzzer 独有的。

这些数字按方案、参数集和库版本分别计数，所以并不是独立 bug 的个数。而且第 7 节会讲到，并不是每个结果都是 bug。

## 6. 几个 bug

大部分真正的 bug 有同一个根源：**同一个值可以写成不止一种字节串，而代码全都接受。**

**NTRU。** 就是文章开头那个 bug。NTRU 密文里存的是 11 位或 13 位的数。在受影响的三个参数集里，总位数不是 8 的倍数（比如 508 × 11 = 5588 位），所以最后一个字节有 4 位没用到。规范规定它们为 0，但解封装从不检查。[修复](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171)只有一行：

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

很多 KEM 在解封装时会重新加密，再把结果和收到的密文逐字节比较，这一步本来能发现问题。我认为 NTRU 漏掉它的原因是它不重新加密，而是直接检查解码后的数，而未用的位在解码时就已经被丢掉了。

较新的签名候选 **SNOVA** 也有同样的问题，出现在部分签名的最后一个字节里。

**Falcon。** Falcon 把签名中的每个数存成一个符号位加上数的大小。解码器把“负零”（符号位为 1、大小为 0）也当作 0 的一种写法，而且不检查末尾的填充是否为 0（[liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315)）。于是同一个签名可以有好几种写法。这件事重要，是因为 Falcon 基于 [GPV 框架](https://eprint.iacr.org/2007/432)，而这个框架通常能提供强不可伪造，用户有理由默认 Falcon 也有。Falcon 团队在规范 1.2 版中修复了它。

**CROSS。** CROSS 的签名长度是固定的，它的验证函数收到了签名长度，却没有使用。所以在合法签名后面追加任意字节，仍然能通过验证（[issue](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)）。这个问题只出现在为 PQClean API 写的版本里，提交给 NIST 的版本检查了长度。

**KNOT-384。** 这是一个哈希函数。消息长度是 6 字节的倍数时，优化代码会多读消息后面的一个字节，于是哈希值取决于内存里紧挨着的内容。守卫字节发现了它。

还有一个发现值得一提。在 2018 年的版本里，有三个 KEM 收到改动过的密文时会崩溃或卡死。崩溃看起来只是健壮性问题，但攻击者能看到它，它等于告诉攻击者“这个密文不合法”。针对 KEM 的攻击恰好可以利用这种“是/否”的回答，一点点恢复私钥。

## 7. 有些结果不是 bug

有些结果根本不是错误，而是方案设计本身造成的。论文把它们叫做“特性”（features），了解它们很有用。

最典型的例子在大多数后量子 KEM 的私钥里，包括 ML-KEM。这些 KEM 用 [Fujisaki–Okamoto（FO）变换](https://doi.org/10.1007/3-540-48405-1_34)达到 IND-CCA 安全。在常见的“隐式拒绝”形式中（[Hofheinz、Hövelmanns、Kiltz](https://eprint.iacr.org/2017/604)），私钥里有一个随机值 `z`。密文不合法时，KEM 不返回错误，而是返回一个由 `z` 生成的假密钥。

![FO 隐式拒绝：合法密文的输出密钥来自 G(m' || h)，拒绝密钥 J(z || c) 虽被计算却被丢弃，因此修改 z 不改变输出](./diagrams/fo-implicit-rejection.svg)

对合法密文，假密钥照样会被计算（让两种情况耗时相同），然后丢弃。所以改动 `z` 之后，解封装合法密文仍然得到正确的密钥。改私钥的那个测试（Test 6）几乎对每个 KEM 都会报告这一点。这不是 bug。但设想一个系统用“解封装一个合法密文”来检查存储的私钥是否完好：`z` 损坏的私钥也能通过，问题要到以后才会暴露。

随机化的 Dilithium 也有类似的性质。它的私钥里有一个值 `K`，只有确定性版本会用到，所以只在 `K` 上不同的两个私钥签出的签名完全一样。标准化后的 ML-DSA 已经在每次签名时都用到 `K`。另外，在 2020 年版本的 LibOQS 里，部分 Rainbow 和 Falcon 的公钥可以被修改，而旧签名在新公钥下仍然能通过验证。这涉及一种叫做排他所有权（exclusive ownership）的性质（[Pornin、Stern](https://doi.org/10.1007/11496137_10)；[Cremers 等](https://eprint.iacr.org/2020/1525)），[Jackson 等](https://eprint.iacr.org/2019/779)的工作表明，缺少这种性质时协议可能出问题。

## 8. 再往前一步：单比特翻转漏掉了什么

这个方法很简单，这也是它的局限：一次只翻转一位，只从一个固定输入出发，而且每个输出只和原输出比较。

为了看看它会漏掉什么，我翻了一遍 [ngcc.dev](https://ngcc.dev/) 上已公开的中国 NGCC 竞赛首轮发现。这是 Markku-Juhani Saarinen 维护的公开评审网站。其中不少 bug 正是这篇论文要找的那一类，但它的测试发现不了。每个这样的 bug 都提示了一条新规则，而这些规则同样不需要知道正确答案。

**改动后的输出要互相比较，而不只是和原输出比较。** Test 7 检查的是改过的密文得到的密钥和真实密钥不同。但在 CheetahKEM 和 LoongKEM 里（[kem-09-1](https://ngcc.dev/reports/kem-09.html)、[kem-18-1](https://ngcc.dev/reports/kem-18.html)），一个写错的掩码让返回的密钥变成了假密钥和真实密钥的混合，真实密钥的大部分比特因此泄露。在 DKEM（[kem-13-1](https://ngcc.dev/reports/kem-13.html)，由我报告）和 BAG-Loong（[kem-03-2](https://ngcc.dev/reports/kem-03.html)）里，假密钥并不依赖整个密文，于是不同的不合法密文会得到同一个假密钥。这些情况下返回的密钥都和真实密钥不同，Test 7 都会通过。解决办法是收集所有改动后的密文得到的密钥，再检查两件事：任意两个都不相同；没有哪个和真实密钥相同的位远超一半。Mouha 等人最初就是把所有输出互相比较的，论文为了适配 AFL++ 放弃了这一点。

**返回码不能泄露任何信息。** DTRU（[kem-14-2](https://ngcc.dev/reports/kem-14.html)）在走拒绝分支时返回了不同的返回码。这会告诉攻击者密文是否合法，而隐式拒绝要隐藏的正是这一点。论文把返回码算作输出的一部分，而输出本来就应该改变，所以发现不了。规则是：使用隐式拒绝时，所有密文的返回码都相同。

**改数值，而不只是改比特。** 很多格式把数存成模某个 `q` 的值。如果解码器把 `x + q` 也当作 `x` 的一种写法，同一个值又有了两种字节串。但翻转一位只会让数值变化 2 的幂，永远不会恰好变化 `q`，所以比特翻转发现不了。QIMEN-PIKE（[kem-31-2](https://ngcc.dev/reports/kem-31.html)）就因此失去了 IND-CCA 安全。最简单的检查是：解码后重新编码，要求得到相同的字节。

**每个长度都往两个方向改。** 论文只把签名长度往短里改。DTRU（[kem-14-1](https://ngcc.dev/reports/kem-14.html)）在收到错误的密文长度时会导致栈缓冲区溢出，Tins（[sign-29-3](https://ngcc.dev/reports/sign-29.html)）在签名长度过长时会导致缓冲区溢出。每个长度参数都应该在 AddressSanitizer 下往短、往长各试一次。

**跨进程比较。** HEP-QC（[kem-17-1](https://ngcc.dev/reports/kem-17.html)）不用传给它的随机数生成器，而是用自己的，而它在每个进程里都从同一个状态开始。同一个进程里先后生成的密钥仍然不同，所以只在一个进程内测试会通过。但每个新进程都生成同一对密钥，任何人都能算出私钥。比较两个新进程生成的第一个密钥，就能发现这个问题。

**实现之间互相比较。** 一个方案通常有参考版本和优化版本。在 FLIT 里（[kem-15-1](https://ngcc.dev/reports/kem-15.html)、[kem-15-2](https://ngcc.dev/reports/kem-15.html)），两个版本得出的密钥不同，而且只有 AVX2 版本会接受大多数不合法的密文。把每个改动后的输入都交给每个版本，要求结果完全一致，就能在不知道正确答案的情况下发现这类 bug。

**有些改动需要了解方案。** 在 TRINE 里（[sign-30-5](https://ngcc.dev/reports/sign-30.html)），把签名的某些部分乘以一个标量，得到的仍是合法签名。在 VDOO 里（[sign-33-7](https://ngcc.dev/reports/sign-33.html)），在消息和签名存放在一起的格式中移动两者的边界，就得到一条新消息的合法签名。随机翻转比特几乎不可能产生这些改动，但只要了解方案的结构，每一种都只需要几行测试代码。

**哈希函数要比较不同长度的消息。** 在 Eijen 里（[hash-09-1](https://ngcc.dev/reports/hash-09.html)），空消息和 7 个零比特组成的消息哈希值相同。只有比较不同长度消息的测试才能看到这一点。

这些新增规则大多完全不需要了解方案。和论文的测试一样，它们可以对竞赛中的每个候选自动运行。

## 9. 自己试一试

作者的代码在 Docker 中运行：`bash run.sh` 启动容器，`bash reproduce.sh ches_liboqs` 复现他们在 LibOQS 0.14.0 上的实验。

不过，要在自己的代码上跑最重要的那个测试，并不需要他们的环境。下面是针对 liboqs 中任意 KEM 的 Test 7，带着第 2 节说的守卫字节。为了简洁，省略了错误处理。

```c
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* 翻转合法密文的每一位，以及两侧守卫字节的每一位。 */
static int test_decaps_ct(const char *name) {
    OQS_KEM *kem = OQS_KEM_new(name);
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    uint8_t *pk = malloc(kem->length_public_key), *sk = malloc(kem->length_secret_key);
    uint8_t *buf = malloc(clen + 2), *ss = malloc(sslen);
    uint8_t *ss0 = malloc(sslen), *ss1 = malloc(sslen);

    OQS_KEM_keypair(kem, pk, sk);
    buf[0] = buf[clen + 1] = 0xFF;                 /* 守卫字节 */
    OQS_KEM_encaps(kem, buf + 1, ss, pk);
    OQS_STATUS rv0 = OQS_KEM_decaps(kem, ss0, buf + 1, sk);

    int bad = 0;
    for (size_t bit = 0; bit < 8 * (clen + 2); bit++) {
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* 在密文内：密钥必须改变 */
        flip(buf, bit);
        OQS_STATUS rv1 = OQS_KEM_decaps(kem, ss1, buf + 1, sk);
        int same = rv0 == rv1 && memcmp(ss0, ss1, sslen) == 0;
        if (same == in_ct) {
            printf("%s: bit %zu: %s\n", name, bit, in_ct ? "same key" : "reads outside c");
            bad++;
        }
        flip(buf, bit);
    }
    OQS_KEM_free(kem);
    return bad;
}

int main(int argc, char **argv) {
    OQS_init();
    return argc == 2 ? test_decaps_ct(argv[1]) != 0 : 2;
}
```

签名的版本是围绕 `OQS_SIG_verify` 的同样一个循环，再加一个尝试所有错误长度的循环。要加上第 8 节的第一条规则，只需把所有改动后的密文得到的密钥保存下来，再互相比较。

如果只从这篇文章里记住几件事，我建议是这些：

- 数据没有填满最后一个字节时，检查未用的位是否为 0。
- 每个值只接受一种编码。解码后重新编码，再比较。
- 检查每一个长度参数，往短往长都要试。
- 在代码的每个版本上（参考实现和优化实现）都跑 Test 7 和 Test 13，并要求结果完全一致。

我[之前那篇关于 PQC 实现工程的文章](../pqc-implementation-guide/?lang=zh)里有一份更长的自查清单，这些测试能覆盖其中好几项。

## 来源

- Fenzi, Gilcher, Virdia，“Finding Bugs and Features Using Cryptographically-Informed Functional Testing”，[TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447)；[ePrint 2024/1122](https://eprint.iacr.org/2024/1122)；[代码](https://github.com/jangilcher/cryptoTesting)。论文 Table 3 列出了每个测试、每个版本的完整结果。
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
- [NTRU 修复：“Ensure trailing bits of ciphertext are 0”](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171)
- [liboqs issue #1315：Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315)
- [CROSS-lib-oqs issue #1：Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)
- [ngcc.dev](https://ngcc.dev/)，NGCC 首轮候选的公开评审（第 8 节引用的发现于 2026-10-21 访问）
