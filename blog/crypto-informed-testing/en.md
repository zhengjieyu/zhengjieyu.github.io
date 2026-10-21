# Flip One Bit: Testing Cryptographic Code Without Knowing the Right Answer

*For anyone who writes or tests cryptographic code · ~15 min read · October 21, 2026*

I recently read a TCHES 2026 paper by Fenzi, Gilcher, and Virdia ([paper](https://doi.org/10.46586/tches.v2026.i1.425-447), [code](https://github.com/jangilcher/cryptoTesting)) on how to test implementations of cryptographic algorithms. My reason for reading it was simple. I have been going through the public review of the first NGCC round, and one kind of implementation bug keeps coming up there. This paper describes a method aimed at exactly that kind of bug.

Here is one of the paper's examples. LibOQS is a fairly widely used C library of post-quantum algorithms, and version 0.4.0, from 2020, included the NTRU KEM. NTRU ciphertexts are not a whole number of bytes long, so the last byte has 4 padding bits, which the specification says must be zero. The decapsulation code did not check them. If you changed any of those bits, the ciphertext still decapsulated, and it gave back the original key.

For a KEM that is a serious problem, and Section 3 explains why. But ordinary testing did not catch it. Nothing crashed, and the known-answer tests passed, because every ciphertext in them was valid.

Below I go through the paper's method and the bugs it found, and then use bugs from the NGCC review to look at what the method still misses.

## 1. Why cryptographic code is hard to test

For most programs, a test compares the output with an answer you already know. With cryptographic code the trouble is that you usually do not have that answer.

The most common approach is the known-answer test (KAT): fix some inputs and compare the outputs with stored results. But the stored results come from the reference implementation, so if the reference is wrong, the KATs are wrong too. KATs also only use valid inputs. A bug like the NTRU one, which only shows up when the ciphertext has been changed, is never exercised.

Tools like AddressSanitizer and [AFL++](https://www.usenix.org/conference/woot20/presentation/fioraldi) do not help much here either. The first only looks at out-of-bounds memory access; the second mostly looks for crashes. The NTRU bug did neither. It returned a wrong result, and that result looked like any other key.

The underlying issue is that cryptographic outputs are meant to look random. A test that gets back `3f a1 9c ...` cannot tell whether that is right. Software testing calls this the oracle problem ([Weyuker, 1982](https://doi.org/10.1093/comjnl/25.4.465)): there is no "oracle" to say whether an output is correct.

## 2. A different approach: compare two outputs

You often cannot tell whether one output is correct, but you often do know how two outputs should relate. Testing based on such relations is called metamorphic testing ([Chen, Cheung, Yiu, 1998](https://arxiv.org/abs/2002.12543); [Chen, Tse, Zhou, 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)).

Take a hash function. We do not know what `H(x)` should be, but two things are certain. If any bit of the message changes, the hash must change. If a byte after the message in memory changes, the hash must not. The first rule checks that no input is ignored; the second checks that nothing outside the input is read. Neither needs the correct answer: change a bit, compute again, compare.

This is not new. In 2018, [Mouha et al.](https://doi.org/10.1109/TR.2018.2847247) applied these two rules to the 86 reference implementations from the SHA-3 competition. 19 broke the first rule and 17 broke the second, including two of the finalists.

The second rule needs guard bytes. You put one extra byte before the input and one after it, and give the function under test a pointer to the real input in between. If changing a guard byte changes the result, the function read out of bounds. The figure shows this for a KEM ciphertext; the orange part is where the NTRU bug was.

![Test 7 buffer layout: a guard byte, the ciphertext marked DIFF including the last byte's padding bits, and a trailing guard byte; flipping the guard must leave the output unchanged, flipping any ciphertext bit must change it](./diagrams/buffer-layout.svg)

Guard bytes are a practical idea because they catch something sanitizers do not. A sanitizer only reports access to memory that was never allocated. If a function reads the next byte of the same, larger buffer, the sanitizer does not care.

## 3. From security definitions to test rules

What the paper does is carry this approach over from hash functions to KEMs and signatures. To me, the most interesting part is that the security definitions of KEMs and signatures can be used directly as test rules.

The standard security goal for a KEM is IND-CCA. Roughly: an attacker may ask the system to decapsulate any ciphertext except the one being attacked, and still learns nothing about the key inside that one.

Back to NTRU. The attacker takes the target ciphertext and changes one padding bit. That gives a "different" ciphertext, which the attacker is allowed to submit for decapsulation, and the system returns the target key. So the bug does not just weaken the scheme. It breaks IND-CCA outright.

Read the other way around, IND-CCA gives a test rule: change any bit of a valid ciphertext, and decapsulation must return a different key.

Signatures work the same way. The usual requirement is that nobody can forge a signature on a new message. Strong unforgeability (sUF-CMA) asks for more: nobody can produce a second, different signature on a message that was already signed. Protocols that use a signature as a unique identifier rely on this. The rule is that changing any bit of a valid signature, or its length, must make verification fail. NIST did not require strong unforgeability, though, so for a scheme that does not claim it, a failure here is not a bug.

## 4. What the test program looks like

Every test follows roughly the same steps. Build a valid input, such as a key pair and a ciphertext, and compute the normal output. Then change one bit of the input and compute again. Finally, check whether the output changed when it should have, and crash on purpose if it did not. The change, recompute, and check steps are repeated for every bit of the input.

The deliberate crash is there so that AFL++ saves the input that caused it. In the paper, AFL++'s own random mutations are switched off; it is only used to run the tests in parallel and keep the results.

![The Test loop: GenInput produces a baseline, Maul flips one bit and states the expectation, Call reruns the function, Match aborts on a mismatch, and AFL++ stores the crashing input](./diagrams/test-loop.svg)

Before flipping single bits, the test also tries three special inputs: unchanged, all zeros, and all ones. The paper splits the loop into four parts, `GenInput`, `Maul`, `Call`, and `Match`. Only `Call` depends on the algorithm; the rest is shared across all schemes.

There are 13 tests in total, covering every input of hashing, key generation, encapsulation, decapsulation, signing, and verification. Where a function uses randomness, the random bytes are fixed so results can be reproduced, and the tests also swap in a random generator that returns the same byte forever, to see whether the implementation then loops forever. For schemes with variable-length signatures, the length field is changed too. The two that matter most are the ones from the previous section: changing the ciphertext before decapsulation (Test 7 in the paper) and changing the signature before verification (Test 13).

## 5. What the tests found

The authors tested four versions of LibOQS (2018, 2020, 2023, and 2025) and the hash functions in SUPERCOP, a benchmarking suite that collects many implementations. They included old versions because LibOQS removes schemes that drop out of the NIST competition, so only old versions still have them. A full run of one version takes about half a day on a server.

For comparison, they also ran an ordinary fuzzer on the same code:

| LibOQS version | Ordinary fuzzer | Additional findings from the new tests |
|---|---|---|
| 2018 | 27 crashes, 1 hang | 3 IND-CCA breaks |
| 0.4.0 (2020) | 17 crashes, 1 hang | 10 IND-CCA breaks, 9 sUF-CMA breaks, 3 buffer overflows |
| 0.8.0 (2023) | nothing | 2 sUF-CMA breaks |
| 0.14.0 (2025) | nothing | 25 sUF-CMA breaks |

The last two rows say the most. On the newer versions the ordinary fuzzer found nothing, and the new tests still found dozens of problems. In the other direction, the new tests found nearly all the crashes the fuzzer found. They missed two, in Dilithium III and Picnic_L3_UR.

These numbers are counted per scheme, parameter set, and version, so they are not counts of distinct bugs. And as Section 7 explains, some of the results are not bugs at all.

## 6. Some of the bugs

Going through these bugs, what struck me is that most of them come from the same place: one value can be written as several different byte strings, and the code accepts all of them.

### NTRU

This is the bug from the introduction. Some numbers: in the three affected parameter sets, the ciphertext is made of 11-bit or 13-bit values packed together. HPS-2048-509, for example, has 508 × 11 = 5588 bits, which is not a multiple of 8, so the last byte has 4 bits left over. The [fix](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171) adds a single check:

```c
/* Check that unused bits of last byte of ciphertext are zero */
fail |= c[NTRU_CIPHERTEXTBYTES-1] & (0xff << (8 - (7 & (NTRU_LOGQ*NTRU_PACK_DEG))));
```

Many KEMs re-encrypt during decapsulation and compare the result with the received ciphertext byte by byte, which would have caught these bits. NTRU does not re-encrypt. It checks the decoded values directly, and the padding bits are already dropped during decoding. My guess is that this is why the problem went unnoticed.

SNOVA, a newer signature scheme, had the same problem in the last byte of some of its signatures.

### Falcon

Falcon encodes each value in a signature as a sign bit plus a magnitude. The decoder accepted "negative zero" (sign bit 1, magnitude 0), and it did not check that the trailing padding was zero ([liboqs issue #1315](https://github.com/open-quantum-safe/liboqs/issues/1315)). So the same signature could be written in several ways. This one is a bit of a shame: Falcon is built on the [GPV framework](https://eprint.iacr.org/2007/432), which should give strong unforgeability, and users would naturally assume it does. The Falcon team fixed it in version 1.2 of the specification.

### CROSS

CROSS signatures have a fixed length, so its verification function simply did not use the signature length it was given. As a result, you could append arbitrary bytes to a valid signature and it would still verify ([issue](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)). This was only in the version written for the PQClean API. The version submitted to NIST did check the length.

### KNOT-384

This is a hash function. When the message length was a multiple of 6 bytes, the optimized code read one byte too many, so the hash depended on whatever came next in memory. This is where the guard bytes from Section 2 paid off.

One more finding is easy to overlook. In the 2018 version, three KEMs crashed or hung when given a modified ciphertext. That looks like a robustness issue, but an attacker can see a crash, and it tells them "this ciphertext was invalid". Known attacks on KEMs use exactly this kind of yes-or-no answer, one query at a time, to recover the secret key.

## 7. Not every result is a bug

Some results come from the design of a scheme rather than from a mistake in the code. The paper calls these "features". I think this part of the paper is good and worth its own section.

The clearest case is a part of the KEM secret key that is normally not used. Most post-quantum KEMs, ML-KEM included, use the [Fujisaki–Okamoto (FO) transform](https://doi.org/10.1007/3-540-48405-1_34) to reach IND-CCA. The common form is "implicit rejection" ([Hofheinz, Hövelmanns, Kiltz](https://eprint.iacr.org/2017/604)): the secret key holds a random value `z`, and for an invalid ciphertext the KEM does not report an error but returns a fake key computed from `z`.

![FO implicit rejection: for a valid ciphertext the output key comes from G(m' || h), and the rejection key J(z || c) is computed but discarded, so changing z does not change the output](./diagrams/fo-implicit-rejection.svg)

For a valid ciphertext the fake key is still computed, so both cases take the same time, and then thrown away. So if you change `z`, a valid ciphertext still decapsulates to the right key. The test that changes the secret key (Test 6) reports this for almost every KEM, and it is not a bug. But a system that checks whether a stored secret key is intact by decapsulating one valid ciphertext would not notice a damaged `z`.

Randomized Dilithium has something similar. Its secret key contains a value `K` that only the deterministic variant uses, so two secret keys that differ only in `K` produce identical signatures. ML-DSA, the standardized version, uses `K` in every signature, so the issue is gone there. Another example is from LibOQS in 2020: some Rainbow and Falcon public keys could be modified, and an existing signature would still verify under the modified key. This relates to a property called exclusive ownership ([Pornin and Stern](https://doi.org/10.1007/11496137_10); [Cremers et al.](https://eprint.iacr.org/2020/1525)), and [Jackson et al.](https://eprint.iacr.org/2019/779) showed that protocols can break when it is missing.

## 8. What single bit flips miss

The method's strength is that it is simple, and so is its limitation: it changes one bit at a time, starts from one fixed input, and compares each output only with the original.

I checked it against the published findings from the first NGCC round on [ngcc.dev](https://ngcc.dev/), a public review site run by Markku-Juhani Saarinen. Quite a few of those findings are the kind of bug this paper is after, yet its tests would not catch them. I grouped them below. Each group suggests one more rule, and none of the rules needs the correct answer either.

### Compare the changed outputs with each other

Test 7 only checks that the key from a changed ciphertext differs from the real key. In CheetahKEM and LoongKEM ([kem-09-1](https://ngcc.dev/reports/kem-09.html), [kem-18-1](https://ngcc.dev/reports/kem-18.html)), the mask used to choose between the keys was wrong, so the returned key was a mix of the fake key and the real one, and most bits of the real key leaked. In DKEM ([kem-13-1](https://ngcc.dev/reports/kem-13.html), which I reported) and BAG-Loong ([kem-03-2](https://ngcc.dev/reports/kem-03.html)), the fake key did not depend on the whole ciphertext, so different invalid ciphertexts got the same fake key. In all these cases the returned key differs from the real key, so Test 7 passes.

The fix is to collect the keys from all the changed ciphertexts and check two more things: no two are equal, and none shares clearly more than half of its bits with the real key. Mouha et al. originally compared all outputs with each other; the paper switched to comparing only with the original output to fit how AFL++ works.

### Return codes can leak too

DTRU ([kem-14-2](https://ngcc.dev/reports/kem-14.html)) returned a different code when it took the rejection branch. That tells an attacker whether a ciphertext was valid, which is exactly what implicit rejection is supposed to hide. The paper does count the return code as part of the output, but a changed ciphertext is expected to give a different output anyway, so the test cannot see this. For an implicit-rejection KEM, the rule should be that every ciphertext gets the same return code.

### Change values, not just bits

Many formats store numbers modulo some `q`. If the decoder accepts `x + q` as another way to write `x`, the same value again has two encodings. Flipping one bit changes a number by a power of two, never by exactly `q`, so bit flips cannot find this. QIMEN-PIKE ([kem-31-2](https://ngcc.dev/reports/kem-31.html)) lost IND-CCA this way. The simplest check is to decode the input, encode it again, and require the same bytes.

### Try lengths in both directions

The paper only shortens the signature length. DTRU ([kem-14-1](https://ngcc.dev/reports/kem-14.html)) overflowed a stack buffer when given a wrong ciphertext length, and Tins ([sign-29-3](https://ngcc.dev/reports/sign-29.html)) overflowed a buffer when the signature length was too long. Every length argument should be tried both shorter and longer, under AddressSanitizer.

### Compare across processes

HEP-QC ([kem-17-1](https://ngcc.dev/reports/kem-17.html)) ignored the random generator passed in through the API and used its own, which started from the same state in every process. Keys generated one after another in the same process were different, so a test inside one process passes. But every new process generated the same key pair, so anyone could compute the secret key. Comparing the first key from two fresh processes catches this.

### Compare implementations

A scheme often has both a reference and an optimized implementation. The two FLIT versions derived different keys ([kem-15-1](https://ngcc.dev/reports/kem-15.html)), and only the AVX2 version accepted most invalid ciphertexts ([kem-15-2](https://ngcc.dev/reports/kem-15.html)). Giving every changed input to every version and requiring identical results finds this kind of bug without knowing the correct answer.

### Some changes need knowledge of the scheme

In TRINE ([sign-30-5](https://ngcc.dev/reports/sign-30.html)), multiplying parts of a signature by a scalar gave another valid signature. VDOO ([sign-33-7](https://ngcc.dev/reports/sign-33.html)) stores message and signature together, and moving the boundary between them gave a valid signature on a new message. Random bit flips will practically never produce these changes, but once you know the structure of the scheme, each one is a few lines of test code.

### For hashes, compare different lengths

In Eijen ([hash-09-1](https://ngcc.dev/reports/hash-09.html)), the empty message and a message of seven zero bits had the same hash. You only see that if you compare messages of different lengths.

Most of these rules do not need any knowledge of the specific scheme, so like the paper's tests they can be run automatically on every candidate in a competition.

## 9. Trying it yourself

The authors' code runs in Docker. Start the container with `bash run.sh`, then run `bash reproduce.sh ches_liboqs` to reproduce their LibOQS 0.14.0 results.

If you just want the most important test on your own code, you do not need all that. The code below runs Test 7 on any KEM in liboqs, with the guard bytes from Section 2. Error handling is left out to keep it short.

```c
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void flip(uint8_t *b, size_t bit) { b[bit / 8] ^= (uint8_t)(1u << (bit % 8)); }

/* Flip every bit of a valid ciphertext and of the guard byte on each side. */
static int test_decaps_ct(const char *name) {
    OQS_KEM *kem = OQS_KEM_new(name);
    size_t clen = kem->length_ciphertext, sslen = kem->length_shared_secret;
    uint8_t *pk = malloc(kem->length_public_key), *sk = malloc(kem->length_secret_key);
    uint8_t *buf = malloc(clen + 2), *ss = malloc(sslen);
    uint8_t *ss0 = malloc(sslen), *ss1 = malloc(sslen);

    OQS_KEM_keypair(kem, pk, sk);
    buf[0] = buf[clen + 1] = 0xFF;                 /* guard bytes */
    OQS_KEM_encaps(kem, buf + 1, ss, pk);
    OQS_STATUS rv0 = OQS_KEM_decaps(kem, ss0, buf + 1, sk);

    int bad = 0;
    for (size_t bit = 0; bit < 8 * (clen + 2); bit++) {
        int in_ct = bit >= 8 && bit < 8 * (clen + 1);  /* inside c: key must change */
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

The signature test has the same structure, with `OQS_SIG_verify` in the loop and a second loop over every wrong length. Adding the first rule from Section 8 is also easy: keep every key the loop produces and compare them pairwise at the end.

To finish, a few suggestions. Wherever data does not fill its last byte, check during decoding that the leftover bits are zero. Accept only one encoding for each value; decoding, re-encoding, and comparing the bytes is an easy way to check. Check every length argument, and try both shorter and longer values. If you have both a reference and an optimized implementation, put Test 7 and Test 13 in CI, run them on every version, and require identical results.

My earlier [post on engineering PQC implementations](../pqc-implementation-guide/) has a longer checklist, and these tests cover several of its items.

## Sources

- Fenzi, Gilcher, Virdia, "Finding Bugs and Features Using Cryptographically-Informed Functional Testing", [TCHES 2026(1), pp. 425–447](https://doi.org/10.46586/tches.v2026.i1.425-447); [ePrint 2024/1122](https://eprint.iacr.org/2024/1122); [code](https://github.com/jangilcher/cryptoTesting). Table 3 of the paper has the full results per test and version.
- Mouha, Raunak, Kuhn, Kacker, "Finding Bugs in Cryptographic Hash Function Implementations", [IEEE Transactions on Reliability 67(3), 2018](https://doi.org/10.1109/TR.2018.2847247)
- Weyuker, "On Testing Non-Testable Programs", [The Computer Journal 25(4), 1982](https://doi.org/10.1093/comjnl/25.4.465)
- Chen, Cheung, Yiu, "Metamorphic Testing: A New Approach for Generating Next Test Cases", [arXiv:2002.12543](https://arxiv.org/abs/2002.12543) (technical report from 1998)
- Chen, Tse, Zhou, "Fault-Based Testing Without the Need of Oracles", [Information and Software Technology 45(1), 2003](https://doi.org/10.1016/S0950-5849%2802%2900129-5)
- Fioraldi, Maier, Eißfeldt, Heuse, "AFL++: Combining Incremental Steps of Fuzzing Research", [USENIX WOOT 2020](https://www.usenix.org/conference/woot20/presentation/fioraldi)
- Gentry, Peikert, Vaikuntanathan, "Trapdoors for Hard Lattices and New Cryptographic Constructions", STOC 2008, [ePrint 2007/432](https://eprint.iacr.org/2007/432)
- Fujisaki, Okamoto, "Secure Integration of Asymmetric and Symmetric Encryption Schemes", [CRYPTO 1999](https://doi.org/10.1007/3-540-48405-1_34)
- Hofheinz, Hövelmanns, Kiltz, "A Modular Analysis of the Fujisaki-Okamoto Transformation", TCC 2017, [ePrint 2017/604](https://eprint.iacr.org/2017/604)
- Pornin, Stern, "Digital Signatures Do Not Guarantee Exclusive Ownership", [ACNS 2005](https://doi.org/10.1007/11496137_10)
- Cremers, Düzlü, Fiedler, Fischlin, Janson, "BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures", IEEE S&P 2021, [ePrint 2020/1525](https://eprint.iacr.org/2020/1525)
- Jackson, Cremers, Cohn-Gordon, Sasse, "Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures", ACM CCS 2019, [ePrint 2019/779](https://eprint.iacr.org/2019/779)
- [NTRU fix: "Ensure trailing bits of ciphertext are 0"](https://github.com/jschanck/ntru/commit/6bb52396fed494001228ca579f4c1d91ef558171)
- [liboqs issue #1315: Malleable Falcon signatures](https://github.com/open-quantum-safe/liboqs/issues/1315)
- [CROSS-lib-oqs issue #1: Potential SUF-CMA violation](https://github.com/CROSS-signature/CROSS-lib-oqs/issues/1)
- [ngcc.dev](https://ngcc.dev/), public review of the NGCC Round 1 candidates (findings cited in Section 8 accessed 2026-10-21)
