"""Characterize."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import time

import numpy as np


class GuardedToolFailure(RuntimeError):
    def __init__(self, result, requested_log):
        self.result = result
        self.log = result.get("log", str(requested_log)) if isinstance(result, dict) else str(requested_log)
        status = result.get("status", "UNKNOWN_TOOL_FAILURE") if isinstance(result, dict) else "UNKNOWN_TOOL_FAILURE"
        super().__init__(f"{status}; tool log: {self.log}")


def _metrics(values, xs, ys, output_width, evidence):
    exact = (xs.astype(np.int64) + ys.astype(np.int64)) % (1 << output_width)
    error = values.astype(np.int64) - exact
    nz = exact != 0
    return {"evidence": evidence, "count": int(error.size),
            "bias": float(error.mean()), "MED": float(np.abs(error).mean()),
            "MRED": float((np.abs(error[nz]) / exact[nz]).mean()) if nz.any() else 0.,
            "error_rate": float(np.count_nonzero(error) / error.size),
            "WCE": int(np.abs(error).max()), "reference": "unsigned_add_mod_output_width",
            "difference_convention": "linear_unsigned_bitpattern_difference_after_output_wrap",
            "MRED_zero_reference": "excluded", "MRED_count": int(nz.sum())}


def _algebra(phi, kap, states, limit=256):
    """Characterize."""
    states = np.asarray(states, dtype=np.int64)
    if states.size > limit:
        return {"status": "UNKNOWN", "reason": "ALGEBRA_STATE_LIMIT", "state_limit": limit}
    t, u = np.meshgrid(states, states, indexing="ij")
    for r in states:
        left = phi[phi[r, t], u]
        right = phi[r, phi[t, u]]
        kl = kap[r, t] + kap[phi[r, t], u]
        kr = kap[t, u] + kap[r, phi[t, u]]
        bad = (left != right) | (kl != kr)
        if bad.any():
            pos = tuple(np.argwhere(bad)[0])
            return {"status": "FAIL", "associative": False,
                    "counterexample": {"r": int(r), "t": int(t[pos]), "u": int(u[pos]),
                                       "phi_left": int(left[pos]), "phi_right": int(right[pos]),
                                       "carry_left": int(kl[pos]), "carry_right": int(kr[pos])}}
    return {"status": "PASS", "associative": True, "checked_triples": int(states.size ** 3)}


def _potential(phi, kap, max_states=256):
    """Characterize."""
    B = len(phi)
    if B > max_states:
        return {"status": "UNKNOWN", "reason": "PSI_STATE_LIMIT", "state_limit": max_states}
    r, t = np.indices((B, B))
    r, t, p = r.ravel(), t.ravel(), phi.ravel()
    ix, cf = (r, t, p), (1, 1, -1)
    mat, rhs = np.zeros((B, B)), np.zeros(B)
    for i in range(3):
        np.add.at(rhs, ix[i], cf[i] * kap.ravel())
        for j in range(3):
            np.add.at(mat, (ix[i], ix[j]), cf[i] * cf[j])
    sol = np.linalg.lstsq(mat, rhs, rcond=None)[0]
    if np.max(np.abs(sol[r] + sol[t] - sol[p] - kap.ravel())) > 1e-7:
        return {"status": "FAIL", "reason": "NO_RATIONAL_PSI"}
    for D in range(1, 4 * B + 1):
        P = np.rint(sol * D).astype(np.int64)
        if np.array_equal(P[r] + P[t] - P[p], D * kap.ravel()):
            return {"status": "PASS", "denominator": D, "psi_times_D": P.tolist(),
                    "verification": "exact_integer_full_pair_table", "checked_pairs": B * B}
    return {"status": "UNKNOWN", "reason": "PSI_DENOMINATOR_NOT_FOUND"}


def certificates(phi, kappa, *, algebra_limit=256):
    phi, kap = np.asarray(phi, dtype=np.int64), np.asarray(kappa, dtype=np.int64)
    B = len(phi)
    if phi.shape != (B, B) or kap.shape != (B, B):
        raise ValueError("phi/kappa must be square matrices of the same shape")
    if np.any(phi < 0) or np.any(phi >= B):
        raise ValueError("phi exceeds the low-state range")
    comm = bool(np.array_equal(phi, phi.T) and np.array_equal(kap, kap.T))
    image = sorted(set(map(int, phi.ravel())))
    reach = set(image)
    while True:
        nxt = reach | set(map(int, phi[sorted(reach), :].ravel()))
        if nxt == reach:
            break
        reach = nxt
    rows, reps, code = {}, [], {}
    for state in sorted(reach):
        row = (tuple(map(int, phi[state])), tuple(map(int, kap[state])))
        if row not in rows:
            rows[row] = len(reps)
            reps.append(state)
        code[str(state)] = rows[row]
    full = _algebra(phi, kap, range(B), algebra_limit)
    img = _algebra(phi, kap, image, algebra_limit)
    psi = _potential(phi, kap, algebra_limit) if full.get("associative") else {"status": "NOT_ASSESSED"}
    if img.get("associative"):
        image_code = {s: i for i, s in enumerate(image)}
        image_phi = np.asarray([[image_code[int(phi[a, b])] for b in image] for a in image])
        image_kap = kap[np.ix_(image, image)]
        image_psi = _potential(image_phi, image_kap, algebra_limit)
        image_psi["states"] = image
        img["psi"] = image_psi
    t1 = {**full, "commutative": comm, "psi": psi,
          "reachable_image": image, "reachable_image_size": len(image),
          "reachable_image_conditions": img,
          "scope": "full_low_operand_domain_for_arbitrary_leaves"}
    t1["liftable"] = bool(full.get("associative") and psi.get("status") == "PASS")
    t1["reachable_image_liftable"] = bool(img.get("associative") and img.get("psi", {}).get("status") == "PASS")
    return {"commutative": comm, "t1": t1,
            "t2": {"status": "PASS", "state_count": len(reps), "row_quotient_m": len(reps),
                   "reachable_state_count": len(reach), "reps": reps, "code": code,
                   "definition": "equal_phi_and_kappa_rows_on_reachable_image",
                   "evidence": "EXHAUSTIVE_LOW_TABLE"}}


def characterize_table(table, width, output_width=None, *, input_widths=None, algebra_limit=256):
    """Characterize."""
    output_width = width + 1 if output_width is None else output_width
    F = np.asarray(table, dtype=np.int64)
    widths = list(input_widths or (width, width))
    na, nb = [1 << w for w in widths]
    if F.shape != (na, nb):
        raise ValueError("Truth-table shape does not match the input widths")
    if output_width < width or output_width > 62 or width > 30:
        raise ValueError("Unsigned output width must cover both inputs and be at most 62 bits")
    if F.min() < 0 or F.max() >= (1 << output_width):
        raise ValueError("Truth-table values exceed the output width")
    xs, ys = np.indices(F.shape, dtype=np.int64)
    residual = (F - xs - ys) % (1 << output_width)
    failed = []
    k_found = None
    for k in range(width):
        B = 1 << k
        mismatch = residual != residual[xs % B, ys % B]
        if not mismatch.any():
            low = F[:B, :B]
            nonbit = (low >> (k+1)) != 0
            if nonbit.any():
                a, b = map(int, np.argwhere(nonbit)[0])
                failed.append({'k': k, 'reason': 'KAPPA_NOT_ONE_BIT',
                               'x': a, 'y': b, 'output': int(low[a, b]),
                               'kappa': int(low[a, b] >> k)})
                continue
            k_found = k
            break
        x_prime, y_prime = map(int, np.argwhere(mismatch)[0])
        hi_a, lo_a, hi_b, lo_b = x_prime // B, x_prime % B, y_prime // B, y_prime % B
        failed.append({"k": k, "x": lo_a, "y": lo_b,
                       "x_prime": hi_a * B + lo_a, "y_prime": hi_b * B + lo_b,
                       "output": int(F[lo_a, lo_b]),
                       "output_prime": int(F[hi_a * B + lo_a, hi_b * B + lo_b]),
                       "residual_mod": int(residual[lo_a, lo_b]),
                       "residual_prime_mod": int(residual[hi_a * B + lo_a, hi_b * B + lo_b])})
    result = {"status": "PASS" if k_found is not None else "REJECTED_NOT_LOCAL",
              "low_local": k_found is not None, "width": width, "input_width": width,
              "input_widths": widths,
              "output_width": output_width, "k": k_found, "k_min": k_found,
              "locality_evidence": "EXHAUSTIVE_FULL_INPUT_DOMAIN", "failed_boundaries": failed,
              "counterexample": failed[-1] if k_found is None and failed else None,
              "commutative": bool(np.array_equal(F, F.T)),
              "metrics": _metrics(F, xs, ys, output_width, "EXHAUSTIVE_FULL_INPUT_DOMAIN"),
              "semantics": "unsigned_modulo_output_width"}
    if k_found is not None and k_found <= min(widths):
        B = 1 << k_found
        low = F[:B, :B]
        phi, kap = low % B, low // B
        result.update({"phi": phi.tolist(), "kappa": kap.tolist(),
                       **certificates(phi, kap, algebra_limit=algebra_limit)})
    elif k_found is not None:
        result.update({"table_status": "UNKNOWN", "reason": "LOW_TABLE_INPUT_DOMAIN_PARTIAL",
                       "t1": {"status": "UNKNOWN"}, "t2": {"status": "UNKNOWN"}})
    else:
        result.update({"t1": {"status": "NOT_APPLICABLE", "associative": False},
                       "t2": {"status": "NOT_APPLICABLE"}})
    return result


class GateEvaluator:
    """Characterize."""
    def __init__(self, module, input_ports=None, output_port=None):
        ports = module["ports"]
        self.inputs = list(input_ports or [p for p, d in ports.items() if d["direction"] == "input"])
        outputs = [p for p, d in ports.items() if d["direction"] == "output"]
        self.output = output_port or (outputs[0] if len(outputs) == 1 else None)
        if len(self.inputs) != 2 or self.output is None:
            raise ValueError("Expected two inputs and one output; specify ports explicitly")
        widths = [len(ports[p]["bits"]) for p in self.inputs]
        if any(ports[p].get("signed", 0) for p in [*self.inputs, self.output]):
            raise ValueError("SIGNED_PORTS_UNSUPPORTED: unsigned certificates required")
        self.input_widths = widths
        self.width, self.output_width = max(widths), len(ports[self.output]["bits"])
        self.ports = ports
        known = {bit for p in self.inputs for bit in ports[p]["bits"]} | {"0", "1"}
        cells = [(name, cell) for name, cell in module.get("cells", {}).items()
                 if cell['type'] != '$scopeinfo']
        self.order = []
        while cells:
            rest = []
            for name, cell in cells:
                inputs = [bit for p, bits in cell["connections"].items()
                          if cell["port_directions"][p] == "input" for bit in bits]
                if all(bit in known for bit in inputs):
                    self.order.append((name, cell))
                    known.update(bit for p, bits in cell["connections"].items()
                                 if cell["port_directions"][p] == "output" for bit in bits)
                else:
                    rest.append((name, cell))
            if len(rest) == len(cells):
                raise ValueError("Noncombinational circuit, cycle, undriven net, or x/z constant")
            cells = rest

    def evaluate(self, xs, ys):
        xs, ys = np.asarray(xs, dtype=np.uint64), np.asarray(ys, dtype=np.uint64)
        bits = {"0": np.zeros(xs.shape, dtype=np.uint8), "1": np.ones(xs.shape, dtype=np.uint8)}
        for port, arr in zip(self.inputs, (xs, ys)):
            for i, bit in enumerate(self.ports[port]["bits"]):
                if isinstance(bit, int):
                    bits[bit] = ((arr >> i) & 1).astype(np.uint8)
        for name, cell in self.order:
            typ = cell["type"]
            c = {p: bits[bs[0]] for p, bs in cell["connections"].items()
                 if cell["port_directions"][p] == "input"}
            A, B = c.get("A"), c.get("B")
            if typ == "$_AND_": val = A & B
            elif typ == "$_OR_": val = A | B
            elif typ == "$_XOR_": val = A ^ B
            elif typ == "$_XNOR_": val = 1 ^ A ^ B
            elif typ == "$_NOT_": val = 1 ^ A
            elif typ == "$_NAND_": val = 1 ^ (A & B)
            elif typ == "$_NOR_": val = 1 ^ (A | B)
            elif typ == "$_MUX_": val = np.where(c["S"], B, A)
            elif typ == "$_BUF_": val = A
            elif typ == "$_ANDNOT_": val = A & (1 ^ B)
            elif typ == "$_ORNOT_": val = A | (1 ^ B)
            else: raise ValueError(f"Unsupported bit gate {name}: {typ}")
            for p, bs in cell["connections"].items():
                if cell["port_directions"][p] == "output":
                    if len(bs) != 1:
                        raise ValueError("Multibit cell remains after techmap")
                    bits[bs[0]] = val
        out = np.zeros(xs.shape, dtype=np.uint64)
        for i, bit in enumerate(self.ports[self.output]["bits"]):
            if bit not in bits:
                raise ValueError("Output contains undriven or x/z bits")
            out |= bits[bit].astype(np.uint64) << i
        return out


def _runner(command, cwd, logfile, runner, timeout=300):
    if runner is None:
        from .runtime import run_guarded
        runner = run_guarded
    result = runner(command, cwd=cwd, log=logfile, memory_mb=3072, timeout=timeout)
    if hasattr(result, "returncode"):
        ok = result.returncode == 0
    elif isinstance(result, dict):
        ok = result.get("returncode", result.get("exit_code", 0)) == 0 and result.get("status", "PASS") not in ("RESOURCE_UNKNOWN", "TIMEOUT", "FAILED")
    else:
        ok = bool(result is None or result == 0)
    if not ok:
        raise GuardedToolFailure(result, logfile)
    return result


def _q(value):
    return '"' + str(value).replace('\\', '/').replace('"', '\\"') + '"'


def _sat_commutativity(files, top, ev, out, yosys, runner, timeout):
    W, O = ev.width, ev.output_width
    if ev.input_widths[0] != ev.input_widths[1]:
        return {"status": "NOT_APPLICABLE", "commutative": None,
                "reason": "UNEQUAL_NATIVE_OPERAND_DOMAINS"}
    a, b = ev.inputs
    miter, log = out / "commutativity.v", out / "commutativity.log"
    miter.write_text(f'''module bear_comm(input [{W-1}:0] x,y, output bad, output [{O-1}:0] f,fp);
{top} a(.{a}(x), .{b}(y), .{ev.output}(f));
{top} b(.{a}(y), .{b}(x), .{ev.output}(fp));
assign bad=f!=fp;
endmodule\n''', encoding="utf-8")
    script = f"read_verilog -sv {' '.join(_q(f.resolve()) for f in files)} {_q(miter)}; hierarchy -top bear_comm; proc; flatten; delete t:$scopeinfo; opt; memory_map; opt; techmap; opt; sat -prove bad 0 -show-inputs -show-outputs"
    run = _runner([yosys, "-Q", "-T", "-p", script], out, log, runner, timeout)
    log = Path(run.get("log", log)) if isinstance(run, dict) else log
    text = log.read_text(encoding="utf-8", errors="replace")
    passed = "SAT proof finished - no model found: SUCCESS!" in text
    failed = "SAT proof finished - model found: FAIL!" in text
    return {"status": "PASS" if passed else "FAIL" if failed else "UNKNOWN",
            "commutative": True if passed else False if failed else None,
            "evidence": "SAT_FULL_INPUT_DOMAIN", "log": str(log)}


def _sat_locality(files, top, ev, k, out, yosys, runner, timeout):
    W, O = ev.width, ev.output_width
    WA, WB = ev.input_widths
    lp, op = ev.inputs, ev.output
    H = O - k
    miter = out / f"locality_k{k}.v"
    ports = ', '.join(f'.{p}({v})' for p, v in zip(lp, ('x', 'y')))
    ports2 = ', '.join(f'.{p}({v})' for p, v in zip(lp, ('xp', 'yp')))
    xe = '(x==xp)' if k >= WA else f'(x[{k-1}:0]==xp[{k-1}:0])'
    ye = '(y==yp)' if k >= WB else f'(y[{k-1}:0]==yp[{k-1}:0])'
    loeq = "1'b1" if k == 0 else f"{xe} && {ye}"
    flo = "1'b1" if k == 0 else f"(f[{k-1}:0]==fp[{k-1}:0])"
    miter.write_text(f'''module bear_miter(input [{WA-1}:0] x,xp, input [{WB-1}:0] y,yp, output bad, output [{O-1}:0] f,fp);
{top} a({ports}, .{op}(f));
{top} b({ports2}, .{op}(fp));
wire [{H-1}:0] r=(f >> {k})-(x >> {k})-(y >> {k});
wire [{H-1}:0] rp=(fp >> {k})-(xp >> {k})-(yp >> {k});
assign bad=({loeq}) && !(({flo}) && (r==rp));
endmodule\n''', encoding="utf-8")
    log, model = out / f"locality_k{k}.log", out / f"locality_k{k}_model.json"
    script = f"read_verilog -sv {' '.join(_q(f.resolve()) for f in files)} {_q(miter)}; hierarchy -top bear_miter; proc; flatten; delete t:$scopeinfo; opt; memory_map; opt; techmap; opt; sat -prove bad 0 -show-inputs -show-outputs -dump_json {_q(model)}"
    run = _runner([yosys, "-Q", "-T", "-p", script], out, log, runner, timeout)
    if isinstance(run, dict) and run.get("log"):
        log = Path(run["log"])
    text = log.read_text(encoding="utf-8", errors="replace")
    if "SAT proof finished - no model found: SUCCESS!" in text:
        return {"k": k, "status": "PASS", "log": str(log)}
    if "SAT proof finished - model found: FAIL!" not in text:
        return {"k": k, "status": "UNKNOWN", "log": str(log)}
    counter = {"k": k}
    if model.exists():
        raw = json.loads(model.read_text(encoding="utf-8"))
        for signal in raw.get("signal", []):
            name = signal.get("name", "").lstrip('\\')
            data = signal.get("data", [])
            if data:
                try: counter[name] = int(data[0], 2)
                except ValueError: counter[name] = data[0]
    counter["model_path"] = str(model)
    if all(isinstance(counter.get(v), int) for v in ('x', 'y', 'xp', 'yp')):
        x, y, xp, yp = [counter[v] for v in ('x', 'y', 'xp', 'yp')]
        fv = int(ev.evaluate([x], [y])[0])
        fpv = int(ev.evaluate([xp], [yp])[0])
        mask, modulus = (1 << k) - 1, 1 << H
        residual = ((fv >> k) - (x >> k) - (y >> k)) % modulus
        residualp = ((fpv >> k) - (xp >> k) - (yp >> k)) % modulus
        same_low = (x & mask) == (xp & mask) and (y & mask) == (yp & mask)
        different = (fv & mask) != (fpv & mask) or residual != residualp
        counter.update({"f_gate": fv, "fp_gate": fpv,
                        "low_inputs_equal": same_low,
                        "phi_output": fv & mask, "phi_output_prime": fpv & mask,
                        "high_residual_mod": residual, "high_residual_prime_mod": residualp,
                        "witness_validated_by_gate_simulation": bool(same_low and different)})
        if not (same_low and different):
            raise ValueError("SAT counterexample disagrees with independent gate evaluation")
    return {"k": k, "status": "FAIL", "counterexample": counter, "log": str(log)}


def _sat_onebit(files, top, ev, k, out, yosys, runner, timeout):
    """Prove all output bits above k zero on the native low-input domain."""
    wa, wb = ev.input_widths
    ow = ev.output_width
    miter, log = out / f'onebit_k{k}.v', out / f'onebit_k{k}.log'
    a, b = ev.inputs
    miter.write_text(f'''module bear_onebit(input [{wa-1}:0] x, input [{wb-1}:0] y, output bad);
wire [{ow-1}:0] f;
{top} u(.{a}(x & {wa}'d{(1 << min(k,wa))-1}), .{b}(y & {wb}'d{(1 << min(k,wb))-1}), .{ev.output}(f));
assign bad=|(f >> {k+1});
endmodule
''', encoding='utf-8')
    script = f"read_verilog -sv {' '.join(_q(f.resolve()) for f in files)} {_q(miter)}; hierarchy -top bear_onebit; proc; flatten; delete t:$scopeinfo; opt; memory_map; opt; techmap; opt; sat -prove bad 0 -show-inputs -show-outputs"
    run = _runner([yosys, '-Q', '-T', '-p', script], out, log, runner, timeout)
    if isinstance(run, dict) and run.get('log'):
        log = Path(run['log'])
    text = log.read_text(encoding='utf-8', errors='replace')
    status = 'PASS' if 'SAT proof finished - no model found: SUCCESS!' in text else 'FAIL' if 'SAT proof finished - model found: FAIL!' in text else 'UNKNOWN'
    return {'status': status, 'log': str(log), 'evidence': 'SAT_LOW_INPUT_DOMAIN'}


def _characterize_impl(files, top, out, *, input_ports=None, output_port=None, yosys="yosys",
                 exhaustive_width=12, max_extract_k=10, samples=100000,
                 seed=20261007, runner=None, timeout=300, algebra_limit=256):
    """Characterize."""
    started = time.monotonic()
    files = [Path(files)] if isinstance(files, (str, Path)) else list(map(Path, files))
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    netlist, log = out / "gates.json", out / "yosys_read.log"
    script = f"read_verilog -sv {' '.join(_q(f.resolve()) for f in files)}; hierarchy -check -top {top}; proc; flatten; delete t:$scopeinfo; opt; memory_map; opt; techmap; opt; clean; write_json {_q(netlist)}"
    run = _runner([yosys, "-Q", "-T", "-p", script], out, log, runner, timeout)
    if isinstance(run, dict) and run.get("log"):
        log = Path(run["log"])
    module = json.loads(netlist.read_text(encoding="utf-8"))["modules"][top]
    ev = GateEvaluator(module, input_ports, output_port)
    W, O = ev.width, ev.output_width
    WA, WB = ev.input_widths
    if W > 32 or O > 62 or O < W:
        raise ValueError("Require unsigned combinational adders with inputs <=32 bits and output covering inputs, <=62 bits")
    if W <= exhaustive_width:
        na, nb = 1 << WA, 1 << WB
        table = np.empty(na * nb, dtype=np.int64)
        for start in range(0, na * nb, 65536):
            idx = np.arange(start, min(start + 65536, na * nb), dtype=np.uint64)
            table[start:start + len(idx)] = ev.evaluate(idx // nb, idx % nb)
        result = characterize_table(table.reshape(na, nb), W, O, input_widths=ev.input_widths,
                                    algebra_limit=algebra_limit)
    else:
        checks = []
        k_found, unknown = None, False
        for k in range(W):
            check = _sat_locality(files, top, ev, k, out, yosys, runner, timeout)
            checks.append(check)
            if check["status"] == "PASS":
                onebit = _sat_onebit(files, top, ev, k, out, yosys, runner, timeout)
                check['onebit'] = onebit
                if onebit['status'] == 'FAIL':
                    check.update(status='FAIL', reason='KAPPA_NOT_ONE_BIT', locality_status='PASS')
                    continue
                if onebit['status'] != 'PASS':
                    check.update(status='UNKNOWN', reason='KAPPA_ONE_BIT_UNKNOWN', locality_status='PASS')
                    unknown = True
                    break
                k_found = k
                break
            if check["status"] == "UNKNOWN":
                unknown = True
                break
        result = {"status": "UNKNOWN" if unknown else "PASS" if k_found is not None else "REJECTED_NOT_LOCAL",
                  "low_local": k_found is not None, "width": W, "input_width": W, "output_width": O,
                  "input_widths": ev.input_widths,
                  "k": k_found, "k_min": k_found, "locality_evidence": "SAT_FULL_INPUT_DOMAIN",
                  "sat_checks": checks,
                  "counterexample": checks[-1].get("counterexample") if k_found is None else None,
                  "semantics": "unsigned_modulo_output_width"}
        if k_found is None:
            label = "UNKNOWN" if unknown else "NOT_APPLICABLE"
            result.update({"t1": {"status": label, "associative": False}, "t2": {"status": label}})
        if k_found is not None and k_found <= max_extract_k and k_found <= min(ev.input_widths):
            B = 1 << k_found
            vals = np.empty(B * B, dtype=np.int64)
            for start in range(0, B * B, 65536):
                ix = np.arange(start, min(start + 65536, B * B), dtype=np.uint64)
                vals[start:start + len(ix)] = ev.evaluate(ix // B, ix % B)
            low = vals.reshape(B, B)
            phi, kap = low % B, low // B
            result.update({"phi": phi.tolist(), "kappa": kap.tolist(),
                           **certificates(phi, kap, algebra_limit=algebra_limit)})
        elif k_found is not None:
            result.update({"table_status": "UNKNOWN", "reason": "EXTRACTION_STATE_LIMIT",
                           "t1": {"status": "UNKNOWN"}, "t2": {"status": "UNKNOWN"}})
        rng = np.random.default_rng(seed)
        xs = rng.integers(0, 1 << WA, size=samples, dtype=np.uint64)
        ys = rng.integers(0, 1 << WB, size=samples, dtype=np.uint64)
        result["metrics"] = _metrics(ev.evaluate(xs, ys), xs, ys, O, "SAMPLED_UNIFORM_NOT_FULL_DOMAIN")
        result["metrics"]["seed"] = seed
        if "commutative" not in result:
            result["commutativity"] = _sat_commutativity(files, top, ev, out, yosys, runner, timeout)
            result["commutative"] = result["commutativity"]["commutative"]
    result.update({"module": top, "top": top, "input_ports": ev.inputs, "output_port": ev.output,
                   "source_sha256": {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                   "elapsed_seconds": time.monotonic() - started, "netlist": str(netlist),
                   "yosys_log": str(log),
                   "reuse": ["residual/solve_psi", "state_classes"]})
    result["native_commutative"] = result.get("commutative") if WA == WB else None
    if WA != WB:
        result["commutativity"] = {"status": "PASS" if result.get("commutative") else "FAIL"
                                    if result.get("commutative") is False else "NOT_APPLICABLE",
                                    "scope": "certified_low_local_extension" if result.get("low_local") else "unequal_native_domains",
                                    "native_status": "NOT_APPLICABLE"}
    (out / "certificate.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def characterize(files, top, out, **kwargs):
    """Characterize."""
    try:
        return _characterize_impl(files, top, out, **kwargs)
    except Exception as error:
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        rec = {"module": top, "top": top, "status": "UNKNOWN", "low_local": None,
               "k": None, "k_min": None, "reason": type(error).__name__, "error": str(error),
               "t1": {"status": "UNKNOWN"}, "t2": {"status": "UNKNOWN"},
               "retry": False}
        if isinstance(error, GuardedToolFailure):
            rec["status"] = error.result.get("status", "UNKNOWN_TOOL_FAILURE")
            rec["tool_log"] = error.log
            rec["returncode"] = error.result.get("returncode")
        elif isinstance(error, MemoryError):
            rec["status"] = "RESOURCE_UNKNOWN"
            rec["resource_scope"] = "inprocess_characterization_memory"
        target = out / "characterize_error.json"
        if target.exists():
            target = out / f"characterize_error_{time.time_ns()}.json"
        target.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        rec["error_log"] = str(target)
        return rec


