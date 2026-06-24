# Blackfin DSP/ALU p-code implementation

Many Blackfin DSP and accumulator instructions were decoded by this SLEIGH
module but emitted `unimpl` (no p-code), so Ghidra's decompiler truncated any
function that reached one (`/* WARNING: Unimplemented instruction */` +
`halt_unimplemented()`). On a real-world firmware image this commonly affects
hundreds of functions — soft-float / fixed-point math libraries, FFT and filter
kernels, colour-space conversion, and JPEG codecs all lean heavily on these
DSP/ALU families.

This change adds p-code for the families that actually occur in such firmware.
Semantics follow the GNU binutils Blackfin simulator (`sim/bfin/bfin-sim.c`) —
the authoritative behavioural reference — and the ADI *Blackfin Processor
Programming Reference*.

## Implemented

- **DIVS / DIVQ** — divide-primitive steps (AQ flag in ASTAT), per `divs()`/`divq()`.
- **ROT** — rotate-through-CC (33-bit), immediate and register count; RLC/RRC.
- **EXTRACT / DEPOSIT** — bit-field extract (z/x) and deposit (x), per `sopcde==10`.
- **ABS / NEG** — saturating scalar; vector `(v)`; accumulator forms.
- **SIGN (signbits)** — modeled as a `signbits` pcodeop (count-leading-sign-bits).
- **POPCNT (ones)** — `popcount`.
- **ASH / LSH** — register-count and immediate, for 32-bit, 16-bit half (SHRD/SHRS),
  vector `(v)`, and 40-bit accumulator destinations.
- **MULT** — DSP 16×16 multiply (`decode_multfunc` + `extract_mult`): half-word
  operand select, modes fu/is/iu/tfu/ih/iss2/s2rnd/t/w32 (sign + fractional <<1),
  full- and half-register and dual-destination writeback.
- **MAC** — multiply-accumulate into 40-bit A0/A1 (load/add/sub), dual, with
  optional rounded half/full-register writeback.
- **Vector ADD/SUB/ADDSUB** (`+|+ -|- +|- -|+`), **MAX/MIN (v)**, accumulator
  **SAT**, accumulator add/sub to registers, and **byteunpack** (pcodeop).

### Completion pass — remaining DSP/ALU families

A follow-up pass cleared the last decoded-but-`unimpl` DSP/ALU constructors so
the module emits p-code for every one of them:

- **Compare accumulator** — `CC = A0 ==/</<= A1`, comparing the 40-bit values
  sign-extended from bit 39.
- **Accumulator add/sub** — `A0 += A1` / `A0 -= A1` (incl. the `w32` variants),
  and **signbits A0/A1**.
- **Round-12 / Round-20** — biased (`+1<<11` / `+1<<19`) arithmetic-shift rounding
  into a 16-bit destination.
- **ROT (accumulator)** — 41-bit rotate-through-CC of `{CC, A[39:0]}`, register
  and immediate count (the 33-bit Dreg ROT widened to the accumulator).
- **Add-on-sign** — dual `SIGN(x)*y` multiply-accumulate, and accumulator
  half-sums (`R = A.L + A.H`).
- **Vector arithmetic shift `(v,s)`** and the dual cross add/sub `SAT` form.
- **EXPADJ** (exponent detect, 4 forms).
- **Video / packed-SIMD via pcodeops** — byteop1p/2p/3p, byteop16p/16m, bytepack,
  SAA, SEARCH, VIT_MAX, BITMUX, BXOR/BXORSHIFT, align8/16/24, DISALGNEXCPT. The
  packed-byte / Viterbi arithmetic is modeled as named p-code operations: the
  source/dest operands are correct and the rounding/shift mode stays in the
  disassembly, but the bit-exact packed result is opaque. This removes the
  decompiler halt while honestly signalling "intricate SIMD here."

## Not modeled (deliberately)

- **Saturation / overflow (V/VS) flag effects** on the saturating variants, and
  exact 40-bit accumulator clamping. The arithmetic dataflow is correct; the
  clamp edge-cases are omitted to keep decompiler output readable. (See the
  `(s)`/`(v,s)`/SAT comments inline.)
- **Packed-byte / Viterbi SIMD internals** (byteop/SAA/VIT_MAX/SEARCH/BITMUX/
  BXOR/align) are intentionally opaque named pcodeops, as above.

## Control-flow / system instructions

A final pass implemented the remaining non-DSP `unimpl` constructors, so the
module now emits p-code for **every** decoded instruction (zero `unimpl`):

- **TESTSET (Preg)** (ISR 11.9): atomic — load the byte at `[Preg]`,
  `CC = (byte == 0)`, then set the byte's MSB (bit 7).
- **CALL/JUMP (PC + Preg)**: PC-relative indexed — target is this instruction's
  address plus `Preg` (`call`/`goto [inst_start + Preg]`).
- **EMUEXCPT** (ISR 11.4, force-emulation) and **ABORT** (`0x2f`, not a documented
  ISA mnemonic) are modeled as named system pcodeops.
- **Blackfin+ 32-bit-immediate JUMP/CALL** (`JUMP(.a)`/`CALL(.a) value`): the
  immediate is taken as the absolute target. The `.r`-bit (plain vs `.a`) variant
  is modeled identically; the blackfin+ reference was not consulted for a separate
  PC-relative base (these are blackfin+-only and absent from classic BF5xx code).

## Mode-id encoding (MULT/MAC)

The `MMOD*`/`MML` sub-tables export a 1-byte mode id: bit 7 = MM (mixed mode),
bits 6:0 = the Blackfin `mmod` number (4=fu 6=tfu 8=is 9=iss2 11=ih 12=iu,
0/1/2/3 = signed fractional/round/trunc). `MUL0/MUL1/MAC0S/MAC1S` export the two
selected 16-bit operands packed as `src0<<16 | src1`.

## ASTAT flag + CC-return additions

A second pass made the soft-float comparators / classifiers decompile (they were
emitting empty `return;` bodies and phantom `in_AZflag`/`in_AC0flag` inputs).

- **DALU status flags.** The D-register ALU ops now write ASTAT: `setflags_add`
  (`AZ`=zero, `AN`=neg, `AC0`=carry, `V`=signed-overflow) on `ADD`; `setflags_sub`
  (`AC0`=`b<=a`=!borrow) on `SUB`/`NEG`; `setflags_nz` (`AZ`/`AN`) on shifts
  (ASHIFT/LSHIFT, reg+imm) and `Dreg += imm7`; `setflags_logical` (`AZ`/`AN`,
  clears `AC0`/`V`) on `AND`/`OR`/`XOR`/`NOT`. Soft-float compares build their
  boolean by accumulating `AZ` into `CC` via `CC |= az` after a `SUB`/`ADD`, so
  these writes are what they read. The decompiler prunes any flag never read, so
  instrumenting the full DALU set is free in the output. (P-register arithmetic
  and 32-bit `MULT` correctly leave ASTAT untouched and are not instrumented.)
- **CC as a return location.** `blackfin.cspec` lists `CCflag` (1 byte) as the
  last `<output>` pentry, so comparators that return their result in `CC`
  (`double_lt/eq/cmp`, …) decompile as `return <expr>` instead of empty. R0 stays
  the preferred return; CC is chosen only when it is the value live at return.

### Semantics reference
Per the **Blackfin DSP Instruction Set Reference** (ADI, Nov 2014): `AZ`="result
zero", `AN`="result negative", `AC0`="result generated a carry" (subtract carry =
!borrow), `V`="result saturates/overflows"; logical & move-ZX ops clear `AC0`/`V`;
shifts affect `AZ`/`AN`/`V` and leave `AC0` unaffected. DIVS/DIVQ (non-restoring
divide, AQ-driven), ROT (33-bit rotate through CC), EXTRACT/DEPOSIT (len bits 4:0 /
pos bits 12:8), MULT mode-select, MAC, vector add/sub, ABS, SIGN(signbits) follow
the reference.

### Coverage
The module emits p-code for **every decoded constructor — zero `unimpl`
remaining**. This includes the full DSP/ALU set plus the remaining control-flow /
system ops (TESTSET, CALL/JUMP (PC+Preg), the blackfin+ 32-bit JUMP/CALL,
EMUEXCPT, ABORT).

Many of the families added in the completion pass (the packed-byte / Viterbi
SIMD in particular) do not appear in every firmware image, so for some targets
this is general module-completeness rather than a required fix; the value is for
Blackfin binaries (codecs, DSP kernels, video) that do use these ops.

### Modeling details (per the ISA reference)
- **Round-12/20** (ISR 10.17/10.18): the inputs are summed into a wider intermediate
  to avoid 32-bit overflow (the ISR pre-shifts the inputs four bits for the same
  reason), then biased and arithmetic-shifted.
- **Add-on-Sign** (ISR 14.1): `SIGN(x)` is `+1`/`-1` decided by the sign **bit**
  alone — there is no zero case (`x >= 0 => +src1`).
- **VIT_MAX** (ISR 14.2) records history bits in **A0**, **BITMUX** (ISR 8.7)
  overwrites **both source registers and A0**, and **SEARCH** (ISR 14.13) updates
  **A0 and A1** as well as the destinations. These clobbers are modeled so the
  decompiler does not propagate stale register values, even though the packed
  result itself stays opaque.
- Compare-accumulator is a signed 40-bit compare (sign-extended from bit 39);
  accumulator ROT is a 41-bit rotate-through-CC.

### Known modeling simplifications (unchanged / acceptable)
- 40-bit accumulator saturation and shift `V`-overflow are not modeled.
- Compare instructions set `CC` only; per the ISA they also affect `AZ`/`AN`/`AC0`
  (from the internal `a-b`). Not modeled because the observed soft-float idioms
  derive `AZ` from an explicit `ADD/SUB`, not from the compare.
