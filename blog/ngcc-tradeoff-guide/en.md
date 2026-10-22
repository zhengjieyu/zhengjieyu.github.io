# From NGCC Data to a Pareto Frontier: Using NGCC Explorer

*October 22, 2026 data snapshot · About 11 min read*

With dozens of new cryptographic candidates, it is tempting to ask which one is “best.” But public keys, ciphertexts, and signatures have different sizes, while key generation, encapsulation, signing, and verification incur different costs. Claimed security strengths and test platforms also differ. A ranking by one number cannot tell an application what it gains and gives up. [NGCC Explorer](../../ngcc-explorer/) makes these costs filterable and traceable, and uses Pareto analysis to expose actual trade-offs.

The numbers in this article belong to the **snapshot synchronized on October 22, 2026**. The site checks for upstream updates; this article does not automatically change with them.

## What is NGCC Explorer, and why build it?

The Institute of Commercial Cryptography Standards (ICCS) [NGCC call](https://www.niccs.org.cn/niccs/Notice/pc/content/content_1975896137741635584.html) includes public-key digital signatures, key encapsulation, and key exchange. Round 1 has many candidates, each with several parameter sets. Reading individual submissions makes it hard to answer a practical question such as “at a comparable claimed security strength, how much computation buys a smaller transmission?”

[PQShield's NIST PQC Signatures Zoo](https://pqshield.github.io/nist-sigs-zoo/) offers a useful presentation model: filters, a scatter plot, and a table for exploring the NIST additional-signature on-ramp and standardized signature schemes. It focuses on **signatures**. According to its [README](https://github.com/PQShield/nist-sigs-zoo#readme), parameter sizes and timings through round 2 came from individual submissions; the project began its own benchmarking from round 3. NGCC Explorer takes inspiration from that exploratory interface, but covers **NGCC Round 1 KEMs and signatures** and adds within-group, two-metric Pareto analysis. The datasets, candidates, and comparison rules are different.

Explorer is neither a standardization outcome nor a security certification, and it does not benchmark implementations in the browser. It organizes public records so that a reader can move from a plotted point to a parameter set, implementation directory, and original measurement file.

## Why synchronize ngcc-harness?

[ngcc-harness](https://github.com/ngcc-dev/ngcc-harness) publishes an independent NGCC Round 1 performance campaign and its raw records: parameter tables, external encoding sizes, test systems, and per-operation measurements. It is useful here for three reasons. **One measurement campaign** gives a more consistent starting point for exploring candidates. **Source files and implementation paths are traceable**, so a number can be checked. **The repository is public and can be synchronized**, allowing the static site to be rebuilt when upstream data changes. NGCC Explorer does not claim that this project or ICCS ran those measurements.

This snapshot contains **749 records: 350 KEM and 399 signature records**. A record represents a parameter set, machine, implementation, and build configuration, **not a distinct algorithm**. The two systems are an Intel Core i7-12700 and a Snapdragon X Elite; 746 records use reference implementations and three use an AVX2 optimized implementation. Timings use upstream mean CPU cycles, while public-key, ciphertext, and signature sizes use external encoding sizes. Missing values are not imputed. The site records the pinned upstream revision and checks for updates daily. See [Data and methods](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/docs/DATA_AND_METHODS.md) for import rules.

## How should the two axes be chosen?

Trade-off analysis uses the current **X and Y selectors**, not a composite score over every metric. The defaults are:

| View | X: communication size | Y: receiver-side operation |
| --- | --- | --- |
| KEM | Public key + ciphertext, bytes | Decapsulation, CPU cycles |
| Signature | Signature, bytes | Verification, CPU cycles |

Both axes are minimized. Combining the KEM public key and ciphertext gives an initial picture of transfer size. If a protocol reuses a public key, **ciphertext size alone** may be a better X axis. A system with frequent verification may care most about verify time; one with a constrained signing device should inspect **sign time** instead. Secret-key storage is another separate cost. **Changing an axis changes the question** and may change the Pareto layers.

Before choosing axes, choose a comparable population. The site compares currently visible records only when they share claimed classical strength, machine, implementation variant, build profile, and compiler flags. The Layer analysis uses 128/256/512-bit strength groups; 192/384-bit variants are currently outside it. Strength is a **claim** from the target table or specification, not a security proof by this site. Records missing either selected value, lacking a comparison group, or failing the relevant known-answer test appear as *Unranked*. Cycles from different machines and Layer 1 points from different configurations must not be merged into one leaderboard.

## What are Pareto optimality and the Layers?

Why not assign one overall rank? Combining bytes and cycles into one score requires a weight: how many cycles is saving one byte worth? Protocols answer that differently. Pareto analysis keeps those trade-offs visible without choosing the weight for the reader.

Suppose A and B are in the same comparable group, with smaller values preferred on both axes. A *dominates* B if A is **no larger on either axis** and **strictly smaller on at least one**. Points that no peer dominates form **Layer 1, the Pareto frontier**. Remove that layer and find the frontier of the remaining points to obtain Layer 2; repeat for Layer 3. There is no first or second place within a layer. Blue only highlights Layer 1 in the interface.

These four real records are all **128-bit KEM, Intel Core i7-12700, reference implementation**, with identical build profiles and compiler flags; their relevant KATs passed. Size is public key plus ciphertext. Cycles are rounded:

| Scheme and parameter set | Public key + ciphertext | Decapsulation | Layer |
| --- | ---: | ---: | ---: |
| [CTL · CTL-257-512](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-12/CTL-257-512__dec.json) | 994 B | 348,951 cycles | 1 |
| [NEV · NEV_512_769_C_ICCS](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-25/NEV_512_769_C_ICCS__dec.json) | 1,127 B | 85,050 cycles | 1 |
| [FLIT · FLIT128_REF](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-15/FLIT128_REF__dec.json) | 1,127 B | 156,917 cycles | 2 |
| [ZEN · ZEN_128](https://github.com/ngcc-dev/ngcc-harness/blob/8f6bd88576b8725b1cf1a19c360290cdddc0e830/performance/data/x86_1/records/kem-41/ZEN_128__dec.json) | 1,127 B | 191,851 cycles | 3 |

CTL transmits **133 fewer bytes** than NEV, while NEV decapsulates about **4.1 times faster**. Neither dominates the other, so both are in Layer 1. NEV and FLIT transfer the same number of bytes, but NEV is faster, keeping FLIT off the first layer. After removing Layer 1, FLIT reaches Layer 2. ZEN has the same 1,127-byte size and is slower again, so it falls in Layer 3. These layers were computed among *all* eligible records in this group, not just these four. They do not mean “NEV is the best KEM overall”; a different machine, axis, or build group requires a fresh comparison.

## What do other candidates show?

The **128-bit signature** results in another shared reference build group on that x86 system also show a trade-off. YuanYang.DSA's `yuanyang-512` has a **561 B** signature and verifies in about **210,750 cycles**. `Rhyme-SHAKE-128` has a **1,483 B** signature and verifies in about **191,214 cycles**. Rhyme verifies slightly faster but its signature is **922 B larger**, so both records are in that group's first layer. The suffix in `yuanyang-512` is a parameter-set name; the **128-bit** grouping here comes from the site's claimed-strength data, not an inference from that suffix.

In the same group, `Rhyme-SM3-128` also has a **1,483 B** signature but takes about **338,813 cycles** to verify. It is therefore dominated by Rhyme-SHAKE on these two default metrics. This says nothing by itself about signing time, other hardware, or the schemes' security assumptions. The Explorer detail panel links to the original records.

## A broader view across the candidates

To avoid drawing a conclusion from a few hand-picked examples, the table takes **the single largest x86/reference build-configuration group** for each primitive and participating claimed strength. It lists the Layer 1 schemes under the default X/Y axes. “Records” counts parameter-set rows, not distinct algorithms; each row's frontier is computed separately. Both the [snapshot data](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/data/normalized.json) and [layer calculation](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/src/lib/analysis.ts) can be checked.

| Primitive | Claimed strength | Records in group | Layer 1 in that group |
| --- | ---: | ---: | --- |
| KEM | 128-bit | 40 | CTL, NEV |
| KEM | 256-bit | 40 | CTL, NEV (two parameter variants) |
| KEM | 512-bit | 40 | NEV |
| Signature | 128-bit | 37 | Facto-DSA, DARTS |
| Signature | 256-bit | 30 | Facto-DSA, VDOO, DARTS |
| Signature | 512-bit | 25 | DOVE, DARTS |

The frontier **changes with primitive and claimed strength**, and often has more than one point. In the 256-bit KEM group, CTL transfers **2,236 B** and decapsulates in about **711,310 cycles**. A compressed NEV variant uses **2,253 B** and about **188,769 cycles**: 17 additional bytes coincide with roughly 522,500 fewer cycles. Another NEV variant uses **2,458 B** and about **186,622 cycles**: another 205 bytes save only about 2,147 cycles. The marginal trade-off differs greatly; an application must decide whether it is worthwhile. A single Layer 1 point in the *selected* 512-bit KEM build group still does not establish a winner across implementations or security considerations.

Other compiler flags, implementations, and machines form different comparison groups. Their frontiers cannot be combined into a universal champion list. Claimed security strength is also not a cryptanalytic result.

These examples support three practical observations: **smaller is not always faster**; one Layer can contain several meaningful trade-offs; and “dominated” means only that a better peer exists on the current two metrics. It does not mean a scheme is less secure, broken, or unsuitable for every deployment. Security analysis, side channels, memory, and protocol-specific key reuse require separate evaluation. A [companion snapshot report](../ngcc-explorer-report/) gives another KEM comparison from a different build group.

## A practical reading workflow

1. In [NGCC Explorer](../../ngcc-explorer/), select KEM or Signature and the relevant claimed strength, machine, and implementation.
2. Read the **units and meaning** of X/Y, then choose size and time metrics that match the protocol bottleneck.
3. Inspect the scatter plot and Layers. Open a candidate to check the parameter set, raw measurement, KAT state, and named better alternatives.
4. Record the comparison scope, snapshot date, and both metrics with the conclusion. Reinterpret the Layers whenever the filters or axes change.

This produces a traceable **local trade-off analysis**, not a universal ranking of NGCC candidates.
