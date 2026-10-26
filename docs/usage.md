# Selection and implementation contracts

`bear.explore.select_curve(candidates, accuracy, hardware, budgets, clocks, metric="task_loss_pp")` consumes existing records and returns a list of choices. Call it with the JSON object shown by the README command; the required keys are candidates, accuracy, hardware, budgets and clocks. Values below describe the schema, not measured results.

- candidates: candidate_id, status=PASS, low_local=true. Arithmetic selection additionally needs MRED or error_rate.
- accuracy: network, dataset, mode (direct or finetuned), candidate_id, seed, accuracy and reference_accuracy in [0,1], drop_pp=100*(reference_accuracy-accuracy), status=PASS or COMPLETE.
- hardware: candidate_id, variant, target_clock_ns, delay_ns, area_um2, power_w (or energy_j_per_cycle), status=PASS or COMPLETE. Re-encoded variants require proof_status=PASS and proof_scope=FULL_PREFIX.
- budgets: positive allowed percentage-point losses; clocks: positive target periods in ns. Hardware measurements must use consistent clocks, stimuli and measurement methods.

The selector excludes unproved or late variants and minimizes area times power among feasible points. Duplicate hardware keys or accuracy seeds are rejected. The inherited policy requires at least three finetuned rows for the literal network name ResNet18 and one for other names. It averages all supplied rows in each group; callers must provide their intended seed set. Direct and finetuned records are not averaged together. optional_finetuning may select either. No evaluation, retraining or measurement is performed here.

For metric=MRED or error_rate, budgets use that metric's units, not percentage points. Characterization records the metric distribution and zero-reference convention. This API does not infer application accuracy from arithmetic error.

## Block and pipeline interfaces

`R_blk_b2` and `R_blk_b4` require clk, rst_n, signed prod_in[15:0], y[31:0], one certified accumulator and the recognized native leaf binding. The supplied first-product behavior is preserved by run/reencode. The implementation split can exceed the minimum certified split. Unsupported inputs return SKIPPED.

`T_blk_q2` and `T_blk_q4` support the direct-feedback contract in README. Balanced `_pipeL2/3/4` variants carry latency=2/3/4 and readout_ports=["y"]; the legacy segmented generator uses latency=L-1. Pass the generated REWRITE.json to verify. Reset semantics and full-prefix scope must be checked in the proof record.

## Shared array readout

`bear array --help` lists the single-design composition interface. Provide original PE files matching the existing PE proof, the actual mux RTL and a selector contract (binary, onehot or onehot0). The supplied examples/array_mux.sv is a minimal adapter, not an evaluation design set. Arithmetic segments L and selector stages M imply d=M+L-1. PE internals and periphery remain integration boundaries.
