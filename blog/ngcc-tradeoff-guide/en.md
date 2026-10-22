# Reading the Trade-off Layers in NGCC Explorer

*About 5 min read · October 22, 2026*

The [NGCC Explorer](../../ngcc-explorer/) puts each measured result on a scatter plot. The Trade-off analysis asks a narrow question: **among comparable results, is there another result that is no worse on either selected axis and strictly better on at least one?** The answer depends on which two axes you select. It is not a score for an algorithm as a whole.

## Which two metrics?

They are the **X axis and Y axis selectors above the plot**. By default:

| View | X axis | Y axis |
| --- | --- | --- |
| KEM | Public key + ciphertext size, in bytes | Decapsulation time, in CPU cycles |
| Signature | Signature size, in bytes | Verification time, in CPU cycles |

Both axes can be changed. For example, replacing decapsulation with encapsulation time asks a different question and can change every layer. The defaults are examples of a communication-size versus computation-time trade-off, not a claim that these are the only relevant costs. Smaller values are preferred on both axes.

## When is one result better than another?

Suppose the selected axes are size and time, and a result is **1,000 bytes and 110 million cycles**. A second result at **900 bytes and 100 million cycles** is better on both axes. One at **900 bytes and 120 million cycles** is smaller but slower, so neither result is unambiguously better on these two axes. The two points represent a trade-off.

The table's “Better on these two metrics” names results that meet this precise rule for the current row. Click a row to see the actual X and Y values of every such result. A named option is better **on these two numbers under the current filters**, not necessarily in security, implementation quality, or an application as a whole.

## What do Layer 1, Layer 2, and Layer 3 mean?

Consider four illustrative results in one comparable group:

| Result | Size (bytes) | Time (million cycles) | Layer |
| --- | ---: | ---: | ---: |
| A | 900 | 100 | 1 |
| B | 800 | 120 | 1 |
| C | 1,000 | 110 | 2 |
| D | 1,100 | 130 | 3 |

A is faster than B, while B is smaller than A. Neither improves both metrics, so **both are in Layer 1**. A is smaller *and* faster than C, which puts C behind the first layer. After removing A and B, C is the best remaining result, so **C is in Layer 2**. Remove C as well and D becomes **Layer 3**.

Layer 1 is the *Pareto frontier* for the selected axes. Later layers are found by repeatedly removing the current frontier. The blue Layer 1 label highlights that first layer. Results in the same layer are **not ordered**: Layer 1 does not mean “the best algorithm,” and Layer 2 does not mean “second place.”

## Which results can be compared?

The Explorer makes these comparisons only among **currently visible results** with the same claimed 128-, 256-, or 512-bit security group, machine, implementation variant, build profile, and compiler flags. The 192- and 384-bit variants are outside this comparison. A result missing either selected measurement, lacking a comparison group, or failing the relevant known-answer test is shown as *Unranked*.

Changing the scheme filters, machine, implementation, or axes can therefore change the layers. CPU cycles from different machines must not be read as one common speed ranking. For the exact source of sizes, timings, and security-group labels, see the project's [data and methods](https://github.com/zhengjieyu/ngcc-benchmark-explorer/blob/main/docs/DATA_AND_METHODS.md).

For a data-backed example, read the [NGCC Explorer report](../ngcc-explorer-report/).
