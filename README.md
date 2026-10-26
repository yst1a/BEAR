# BEAR — Bit-Exact Accumulator Re-encoding

BEAR makes approximate accumulators faster without changing what they compute.
An approximate adder usually approximates only its low bits and adds the high bits exactly, but its exact high-bit carry chain still sits in the accumulation loop.
BEAR splits the accumulator where the approximation ends: the low bits keep the original approximate logic, the exact high bits are stored in carry-save form, and a single boundary carry crosses the split.
The rewritten accumulator produces the same output bits as the original in every cycle, so networks validated on the original hardware run on the new one without retraining.
BEAR proves this equivalence formally for every design it emits.

![BEAR flow](docs/bear_flow.png)

## What you give and what you get

| You give | You get |
|---|---|
| The RTL of an accumulator built from an approximate adder | Re-encoded RTL with the same ports and control (optionally with a pipelined readout) |
| The RTL of the adder (as a manifest) | A certificate of where the approximation ends (`k`, low-bit function, boundary carry) |
| Optionally, a Liberty library and timing budgets | A formal proof that every output bit matches the original from reset |
| | Timing and area points, and the selected design for your budget |

## Install

Requirements: Linux (or WSL), Python 3.10 or newer, NumPy 1.24 or newer, Yosys with ABC, Verilator, and a C++ compiler with `make`.
Optional: SymbiYosys and Z3 (alternative proof engine), OpenSTA with a Liberty library (timing-based selection), PyTorch 2.1 or newer (bit-exact tensor model export).

```sh
python -m pip install .
python -m pip install '.[export]'     # optional: tensor model export
```

Put the tools on `PATH`, or point to them with `BEAR_YOSYS`, `BEAR_YOSYS_ABC`, `BEAR_VERILATOR`, `BEAR_SBY`, `BEAR_Z3` and `BEAR_STA`.
`BEAR_WORK_DIR` selects where intermediate files go.
The package was checked with Python 3.12, Yosys 0.69 and SymbiYosys 0.69.

## Quick start

```sh
python examples/minimal.py --out output/minimal
```

This takes an 8-bit accumulator built from a lower-part-OR adder (`examples/loa_accumulator.v`), finds where its approximation ends, rewrites it, and proves the rewrite equivalent.
The rewritten RTL is `output/minimal/rewrite/candidate.v`; the script fails unless the proof passes over the full prefix from reset.
No timing library is needed.

## Step by step

The five commands below correspond to the five steps of the flow figure.

```sh
# 1. Characterize: find where the adder's approximation ends
bear characterize examples/loa_accumulator.v --top loa8 --out output/cert

# 2. Extract: find the accumulator registers built on that adder
bear extract examples/loa_accumulator.v --top loa_accumulator --adders examples/adders.json --out output/detect

# 3. Re-encode: generate carry-save candidates and their state relations
bear reencode output/detect/DETECTION.json --certificates output/cert/certificate.json --variant T_cs --out output/rewrite

# 4. Verify: prove the candidate equal to the original in every output bit
bear verify examples/loa_accumulator.v output/rewrite/candidate.v --top loa_accumulator \
     --refinement output/rewrite/REWRITE.json --out output/proof

# 5. Select: pick the cheapest proven design that meets your budget
bear select points.json --proofs proofs.json --budgets 2000 --out output/selection.json
```

`bear run` performs steps 1 to 5 for one design, including synthesis and timing when you pass `--liberty` and `--constraints`.

## Commands

| Command | What it does | Main arguments |
|---|---|---|
| `characterize` | Checks that an adder has an exact split at some bit `k` and reads the low-bit function and boundary carry from its netlist (exhaustively for narrow adders, by SAT otherwise). | RTL files, `--top`, `--out` |
| `extract` | Finds registers that one characterized adder updates and reads back, with their reset, load and hold control. | RTL files, `--top`, `--adders manifest.json`, `--out` |
| `reencode` | Writes candidate RTL in carry-save form, plus `REWRITE.json` with the state relation and readout latency. | `DETECTION.json`, `--certificates`, `--variant`, `--block-size 2\|4`, `--out` |
| `verify` | Proves the candidate equal to the original by induction on the state relation, then cross-checks by simulation. | original and candidate RTL, `--top`, `--refinement REWRITE.json`, `--latency d`, `--formal-engine yosys_sat\|sby`, `--out` |
| `select` | Picks a proven design from measured timing and area points. | `points.json`, `--proofs proofs.json`, `--budgets` (ps), `--objective area@budget\|fastest`, `--out` |
| `run` | Steps 1 to 5 for one design. | `--adders`, `--top`, `--liberty`, `--constraints`, `--budgets`, `--out` |
| `interface` | Emits an accumulator or MAC shell around a given adder, useful for trying BEAR on an adder alone. | `--top`, `--adder-module`, `--width`, `--input-width`, `--mode ACC\|MAC`, `--out` |
| `export` | Emits a bit-exact tensor model of the accumulator from its certificate. | certificate JSON, output Python file |
| `array` | Generates and proves a readout shared by a column of processing elements. | `--pe`, `--pe-proof`, `--mux`, `--mux-top`, `--n`, `--width`, `--k`, `--out` |

Run `bear <command> --help` for all options.

## Variants

- `T_cs`: full carry-save form; each high bit has one full adder in the loop.
- `T_blk_q2`, `T_blk_q4` (or `--block-size 2|4`): block-wise form; the high bits are split into 2- or 4-bit blocks and only the block carries are registered, which saves registers.
- `*_pipeL2`, `*_pipeL3`, `*_pipeL4`: the final addition outside the loop is pipelined into `d` = 2, 3 or 4 stages. The outputs then arrive `d` cycles later and read 0 for `d` cycles after a reset; pass `REWRITE.json` to `verify` so that the proof uses the same delay.

```sh
bear reencode output/detect/DETECTION.json --certificates output/cert/certificate.json --block-size 2 --out output/block
```

## Selecting with an accuracy budget

To choose among several approximate functions under an accuracy budget, call `bear.explore.select_curve` with your own accuracy and hardware measurements; it returns, for each target clock and loss budget, the proven design with the lowest area×power.
The input format is described in [docs/usage.md](docs/usage.md). BEAR itself does not run networks or retrain them.

## Inputs and limits

- The adder must be a combinational two-input adder (up to 32 input bits) whose approximation is confined to the low bits. Adders whose approximation reaches the top bit cannot be split and are left unchanged.
- Signed operands must be sign-extended before the full-width adder; arithmetic wraps around without saturation.
- The accumulator needs a positive-edge clock; the block-wise and pipelined paths expect an asynchronous active-low reset and supported enable or hold control. Unsupported structures are reported as `SKIPPED`, never silently rewritten.
- Only results with `PASS` and scope `FULL_PREFIX` are proven; `UNKNOWN`, `NOT_ASSESSED` and `SKIPPED` are not.
- The proof covers the cycle-level RTL. Check synthesized netlists in your usual flow.
- Timing-based selection uses an adapter written for the NanGate 45 nm library; other libraries need the constraints in the adapter reviewed.

## Outputs

| File | Written by | Content |
|---|---|---|
| `certificate.json` | `characterize` | split bit `k`, low-bit function, boundary carry, error statistics |
| `DETECTION.json` | `extract` | accumulator registers, operands, control |
| `candidate.v`, `REWRITE.json` | `reencode` | rewritten RTL, state relation, readout latency |
| `receipt.json`, proof logs | `verify` | proof status and scope, simulation record |
| `RUN.json`, `REPORT.md`, `rewritten.v` | `run` | the whole flow for one design |

## Tests

```sh
python -m unittest discover -s tests -v
BEAR_INTEGRATION=1 python -m unittest discover -s tests -v   # also runs tool-dependent tests
```

## License

MIT. Copyright (c) 2026 Anonymous Authors.
