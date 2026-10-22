# 从 NGCC 数据到 Pareto 前沿：如何使用 NGCC Explorer

*2026 年 10 月 22 日数据快照 · 约 11 分钟阅读*

面对几十种新的密码方案，很容易问“哪一个最好”。但公钥、密文和签名占用空间，密钥生成、封装、签名与验证又各有耗时；安全强度和测试平台也不相同。一个按单项指标排序的榜单，回答不了具体应用需要付出什么代价。[NGCC Explorer](../../ngcc-explorer/) 的目标是让这些成本可筛选、可追溯、可并排查看，再用 Pareto 分析标出真正存在的取舍。

本文的数值固定在 **2026 年 10 月 22 日同步的数据快照**。网站会检查上游更新，本文不会随之自动改写。

## NGCC Explorer 是什么，为什么做它？

商用密码标准研究院（ICCS）的 [NGCC 征集](https://www.niccs.org.cn/niccs/Notice/pc/content/content_1975896137741635584.html)涵盖数字签名、密钥封装和密钥交换等公钥算法。第一轮有大量候选方案，每种方案又有多个参数集。单看提交文档，很难回答“在相近声称安全强度下，少传多少字节要付出多少计算开销”这样的问题。

[PQShield 的 NIST PQC Signatures Zoo](https://pqshield.github.io/nist-sigs-zoo/) 给了一个有用的展示思路：用筛选器、散点图和表格探索 NIST 附加签名征集及标准化签名方案。它聚焦**签名**，其早期参数与耗时数据主要来自各方案提交文档；其 [README](https://github.com/PQShield/nist-sigs-zoo#readme) 说明，从第三轮起才进行自己的 benchmark。NGCC Explorer 借鉴这种“先探索、再点开证据”的交互思路，但覆盖 **NGCC 第一轮的 KEM 与签名**，并增加同组、双指标的 Pareto 分析。两站的数据来源、比较对象和评价口径并不相同。

Explorer 不是标准化结论或安全认证，也不是在浏览器中运行密码实现的 benchmark。它把公开记录组织起来，让读者能从图表走到参数集、实现目录和原始测量文件。

## 为什么同步 ngcc-harness？

[ngcc-harness](https://github.com/ngcc-dev/ngcc-harness) 发布了独立的 NGCC 第一轮性能测试及原始记录，包括参数表、外部编码大小、测试机器和逐项操作的测量文件。选择它有三个实际原因：**同一次测试活动**为跨方案查看提供较一致的起点；**原始文件和实现路径可追溯**，每个数字都能回查；**公开仓库可同步**，上游修订后可以重新生成静态网站。NGCC Explorer 不声称这些测试由本站或 ICCS 运行。

本次快照包含 **749 条记录，其中 KEM 350 条、签名 399 条**。一条记录是某参数集在某机器、实现及构建配置下的一组结果，不等于一种独立算法。测试机器为 Intel Core i7-12700 和 Snapdragon X Elite；746 条记录使用 reference 实现，3 条使用 AVX2 优化实现。性能取上游的平均 CPU cycles，公钥、密文和签名大小取外部编码大小；缺失值不推算。网站保存对应的上游版本并每日检查是否有更新。导入规则见 [Data and methods](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/docs/DATA_AND_METHODS.md)。

## 两个坐标轴怎样选？

Trade-off analysis 比较的是图上当前选择的 **X 和 Y 两个指标**，不是所有指标的综合分。默认设置是：

| 页面 | 横轴 X：通信大小 | 纵轴 Y：接收方操作 |
| --- | --- | --- |
| KEM | 公钥 + 密文，字节 | 解封装，CPU cycles |
| Signature | 签名，字节 | 验证，CPU cycles |

两个轴都按越小越好处理。默认横轴为 KEM 合并公钥与密文，便于初看传输成本；如果公钥会长期复用，改看**密文大小**可能更符合协议。验证频繁但签名很少的场景，可以把纵轴设为验证；签名端受限时则应改看**签名耗时**。密钥存储重要时还应检查秘密密钥大小。**换轴就是换问题**，Pareto 层也可能变化。

选轴之前还要选可比范围。网站只在当前筛选后仍可见、且声称经典安全强度、机器、实现版本、构建配置和编译参数相同的记录中比较。页面用于比较的强度组为 128/256/512-bit；192/384-bit 变体暂不参与 Layer 计算。这里的强度是目标表或规格书中的**声称值**，并非本站证明安全。缺少任一轴数据、没有对应比较组，或相关已知答案测试未通过的记录显示为 *Unranked*。不同机器的 cycles、不同配置的 Layer 1 不应合并为一个排行榜。

## Pareto 最优和 Layer 到底是什么？

为什么不直接给一个总排名？因为把字节与 cycles 加成一个分数，必须先指定“省 1 字节值多少 cycles”。不同协议会给出不同答案；Pareto 方法先保留这些取舍，不替读者决定权重。

设 A、B 在同一个可比组，且两项指标都是越小越好。若 A 的 X、Y **都不大于** B，并且**至少一项严格更小**，就说 A 在这两个指标上*支配* B。没有任何同组记录支配的点，组成 **Layer 1，也叫 Pareto frontier（帕累托前沿）**。移除 Layer 1，再找剩余点的前沿，得到 Layer 2；重复可得 Layer 3。层内没有第一、第二名，蓝色只是在页面上突出第一层。

下面四条都是快照中的真实 **128-bit KEM、Intel Core i7-12700、reference 实现**，具有相同构建配置与编译参数，并通过相关 KAT。大小为公钥加密文，cycles 四舍五入：

| 方案与参数集 | 公钥 + 密文 | 解封装 | Layer |
| --- | ---: | ---: | ---: |
| [CTL · CTL-257-512](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-12/CTL-257-512__dec.json) | 994 B | 348,951 cycles | 1 |
| [NEV · NEV_512_769_C_ICCS](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-25/NEV_512_769_C_ICCS__dec.json) | 1,127 B | 85,050 cycles | 1 |
| [FLIT · FLIT128_REF](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-15/FLIT128_REF__dec.json) | 1,127 B | 156,917 cycles | 2 |
| [ZEN · ZEN_128](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-41/ZEN_128__dec.json) | 1,127 B | 191,851 cycles | 3 |

CTL 比 NEV **少 133 B**，NEV 的解封装则约快 **4.1 倍**；两者各有优势，因此都在第一层。NEV 与 FLIT 传输大小相同，解封装更快，所以 FLIT 不在第一层。移除第一层后，FLIT 成为第二层；ZEN 的大小同为 1,127 B、耗时又高于 FLIT，因此落在第三层。这张表不表示“NEV 是全体 KEM 第一名”：上述 Layer 是在这一组全部可比记录中算出的，换机器、指标或构建组就要重新计算。

## 从其他方案能读出什么？

同一台 x86 机器、同一 reference 构建组的 **128-bit 签名**也展示了取舍：YuanYang.DSA 的 `yuanyang-512` 签名为 **561 B**、验证约 **210,750 cycles**；Rhyme 的 `Rhyme-SHAKE-128` 为 **1,483 B**、约 **191,214 cycles**。Rhyme 验证略快，但签名多 **922 B**，所以这两条记录都在该组的第一层。注意 `yuanyang-512` 是参数集名称，这里的 **128-bit** 来自网站所用的声称安全强度分组；不要从名称末尾推断分组。

在该组中，`Rhyme-SM3-128` 与 Rhyme-SHAKE 的签名同为 **1,483 B**，验证约 **338,813 cycles**，因此在这两个默认指标上被后者支配。这个结论只比较签名长度与验证耗时；换成签名耗时、其他硬件，或考虑设计假设，答案可能不同。相关原始文件可从 Explorer 的详情面板打开。

## 全部方案比较后的分层概览

为了不只挑选几个例子，下表对每种类型、每个参与分析的声称强度，**只取 x86/reference 中记录最多的单一构建配置组**，在默认 X/Y 轴上列出第一层。这里的“记录数”是参数集记录数，不是算法数；每行都在本行的组内独立计算。生成表格所依据的 [快照数据](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/data/normalized.json) 和 [分层规则](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/src/lib/analysis.ts) 均可复核。

| 类型 | 声称强度 | 组内记录 | 该组 Layer 1 的方案 |
| --- | ---: | ---: | --- |
| KEM | 128-bit | 40 | CTL、NEV |
| KEM | 256-bit | 40 | CTL、NEV（两个参数变体） |
| KEM | 512-bit | 40 | NEV |
| Signature | 128-bit | 37 | Facto-DSA、DARTS |
| Signature | 256-bit | 30 | Facto-DSA、VDOO、DARTS |
| Signature | 512-bit | 25 | DOVE、DARTS |

这个概览能说明**前沿会随类型和声称强度变化**，也显示同一前沿常不止一个点。例如 256-bit KEM 的组内，CTL 传输 **2,236 B**、解封装约 **711,310 cycles**；NEV 的压缩变体为 **2,253 B**、约 **188,769 cycles**。多 17 B 换来约 52.3 万 cycles 的减少。另一个 NEV 变体则为 **2,458 B**、约 **186,622 cycles**：再多 205 B，只减少约 2,147 cycles。这两个权衡的“斜率”差别很大，是否值得由应用决定。表中 512-bit KEM 在*该构建组*只有一个第一层点，仍不能推出它在所有实现或其他安全维度上“最好”。

其他编译参数、实现和机器形成别的比较组；把它们的第一层合并成总冠军没有依据。记录中的安全强度也只是声称值，不能拿性能前沿替代密码分析。

这些例子带来三个实际结论：**更小并不总是更快**；同一个 Layer 可以容纳多种取舍；被支配只说明当前两个指标上存在同组更优记录。它不等于安全性较差、实现有漏洞，或在所有应用中都应被淘汰。签名与 KEM 的安全分析、侧信道风险、内存占用和协议中的密钥复用，都需要另行判断。[另一篇数据观察报告](../ngcc-explorer-report/?lang=zh) 还给出了不同编译组的 KEM 例子。

## 一次实际使用流程

1. 在 [NGCC Explorer](../../ngcc-explorer/) 选 KEM 或 Signature，再选与你的需求对应的声称强度、机器和实现。
2. 先读 X/Y 的**单位与含义**，再按协议瓶颈选择大小、耗时或其他可用指标。
3. 看散点图与 Layer；点开候选记录，核对参数集、原始测量、KAT 状态和列出的更优替代。
4. 把比较范围、快照日期和两项指标与结论一起记录。若改变筛选条件或坐标轴，就重新读 Layer。

这样得到的是一份有来源、可复查的**局部取舍分析**，而不是为所有 NGCC 方案排出的总名次。
