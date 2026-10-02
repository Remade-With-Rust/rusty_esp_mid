# Generators for the vendored p256 (round 3)

- `gen_gtable.py` writes `p256/src/arithmetic/generator_table.rs`: the
  fixed-base table for primeorder's comb (signed 5-bit digits, 52 rows of
  16 multiples), from exact Python integers. `python gen_gtable.py [dst]`.
- `gen_asm_mul.py` emits `fe_mul_xtensa`, the CIOS field multiply in
  Xtensa asm with every carry by `saltu` (as `.byte`: LLVM's assembler does
  not know the instruction). `rust_fn_fixed()` is the text in `field32.rs`.
- `gen_asm_add.py` emits an asm field add and subtract and checks every
  instruction sequence against Python's integers in a small interpreter.
  **Refuted on the chip** (no faster: an add costs its call and its arrays,
  not its carries); kept for the record, not used.

The ledger is `../../docs/LEDGER.md`, "Round 3".
