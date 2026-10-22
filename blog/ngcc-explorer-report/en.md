# NGCC Explorer Report: Reading the Size–Speed Trade-off

*October 22, 2026 data snapshot · About 7 min read*

[NGCC Explorer](../../ngcc-explorer/) brings published NGCC Round 1 parameters and performance records into one filterable view. This report uses the **snapshot synchronized on October 22, 2026** to show how to read communication size against computation time. The site checks for upstream updates, but the numbers in this article remain tied to this snapshot. For an introduction to Layer 1, 2, and 3, see the [chart-reading guide](../ngcc-tradeoff-guide/).

## What the data covers

The snapshot contains **749 records: 350 KEM and 399 signature records**, imported from the independent Round 1 campaign in [ngcc-harness](https://github.com/ngcc-dev/ngcc-harness/tree/8f6bd88576b8725b1cf1a19c360290cdddc0e830). A record identifies a parameter set, machine, implementation, and build configuration; it is **not a distinct algorithm**. Measurements cover an Intel Core i7-12700 and a Snapdragon X Elite. Of the records, 746 are reference implementations and three use an AVX2 optimized implementation. The Explorer organizes these published results; it does not rerun the benchmarks.

Timings use the upstream mean CPU cycles. Public-key, ciphertext, and signature sizes use the reported external encodings. Missing measurements are not filled in. Displayed 128/256/512-bit values are **claimed classical security strengths** from target tables or specifications, not an independent security assessment. See [Data and methods](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/docs/DATA_AND_METHODS.md) for provenance and import rules.

## What the default axes measure

For KEMs, X is **public key + ciphertext (bytes)** and Y is **decapsulation (cycles)**. For signatures, X is **signature size (bytes)** and Y is **verification (cycles)**. Smaller is preferred on both axes. The combined KEM size gives an initial view of communication cost, although a protocol may reuse a public key; either component can be selected separately. Decapsulation and verification represent receiver-side operations in the default view. Key generation, encapsulation, and signing times can also be selected.

## One measured trade-off

The following records are all **128-bit KEM, Intel Core i7-12700, reference implementation**, with the same build profile and compiler flags. Cycles are rounded to whole numbers; sizes sum the public key and ciphertext.

| Parameter set | Public key + ciphertext | Decapsulation |
| --- | ---: | ---: |
| BW-KEM · BW_KEM_C128 | 1,552 B | 338,701 cycles |
| DKEM · DKEM-128 | 1,600 B | 254,308 cycles |
| BRA · BRA-128 | 3,170 B | 50,590,354 cycles |

BW-KEM transfers **48 fewer bytes** than DKEM. DKEM uses **about 84,393 fewer cycles** for decapsulation. Neither dominates the other on these axes: the smaller of the two is slower. BRA is larger and slower than both, so both are better alternatives to it on the selected metrics. “Better” here is an explicit **coordinate-by-coordinate comparison**, not an overall score for a scheme.

## What a Layer can tell us

A record belongs to **Layer 1** when no record in its comparison group is no worse on both selected axes and strictly lower on at least one. Remove that layer and repeat to obtain Layer 2, Layer 3, and so on. BW-KEM and DKEM illustrate how the first layer can contain different trade-offs; BRA is kept off that first layer by better alternatives.

A Layer is **local to the current axes, filters, and comparison group**. The Explorer groups records by claimed strength, machine, implementation, build profile, and compiler flags before comparing them. Layer 1 points from separate groups do not form a site-wide winner list. Changing the axes or filters can change the layers. The 192- and 384-bit variants are currently outside this Layer analysis; records missing a selected metric or failing a relevant known-answer test are excluded too. Layer 1 only says that no qualifying alternative was found on these two costs. It cannot replace security analysis, side-channel evaluation, or a deployment-specific decision.

## How to use the analysis

On the [NGCC Explorer](../../ngcc-explorer/) page, first select the claimed strength and machine relevant to you, then choose X/Y metrics that match your protocol. Open a record to inspect its parameter set, implementation source, missing values, and named better alternatives. If key storage, sender-side time, or another platform matters more, change axes and look again. When citing a number, include the **snapshot date, machine, and selected metrics** because the site's data may change.
