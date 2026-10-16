"""Extract."""
from __future__ import annotations
import json
from pathlib import Path
import re
import time


def _certs(certificates):
    if isinstance(certificates, dict):
        if "records" in certificates:
            certificates = certificates["records"]
        elif "module" in certificates:
            certificates = [certificates]
        else:
            certificates = list(certificates.values())
    return {c.get("module", c.get("name")): c for c in certificates}


def _integer(value):
    if isinstance(value, int):
        return value
    return int(value or "0", 2)


def _quote(value):
    return '"' + str(value).replace('\\', '/').replace('"', '\\"') + '"'


class NetGraph:
    def __init__(self, module, certificates, modules=None):
        self.module = module
        self.cells = module.get("cells", {})
        self.certificates = _certs(certificates)
        self.modules = modules or {}
        self.adders = {}
        self.drivers = {}
        self.bit_drivers = {}
        self.registers = {}
        for name, cell in self.cells.items():
            typ = cell["type"]
            mod = self.modules.get(typ, {})
            hdlname = mod.get("attributes", {}).get("hdlname", "").split()
            aliases = {typ} | set(hdlname[:1])
            cert = None
            for candidate in self.certificates.values():
                if not aliases & {candidate.get('module'),candidate.get('name'),candidate.get('match_module')}:
                    continue
                actual_params = {**mod.get('parameter_default_values',{}), **cell.get('parameters',{})}
                required = candidate.get('parameters',{})
                if required and any(key not in actual_params or _integer(actual_params[key]) != value for key,value in required.items()):
                    continue
                cert = candidate
                break
            if cert is not None:
                self.adders[name] = cert
            if typ in ("$dff", "$adff", "$dffe", "$adffe", "$sdff", "$sdffe", "$sdffce"):
                self.registers[name] = cell
            for port, bits in cell.get("connections", {}).items():
                if cell.get("port_directions", {}).get(port) == "output":
                    self.drivers[tuple(bits)] = (name, port)
                    for bit in bits:
                        if isinstance(bit,int):
                            self.bit_drivers[bit]=(name,port)

    def adder_ports(self, name):
        cert = self.adders[name]
        cell = self.cells[name]
        inputs = cert.get("input_ports", [])
        output = cert.get("output_port")
        if len(inputs) != 2 or not output or any(p not in cell['connections'] for p in inputs+[output]):
            inputs = [p for p, d in cell.get("port_directions", {}).items() if d == "input"]
            outputs = [p for p, d in cell.get("port_directions", {}).items() if d == "output"]
            if len(inputs) != 2 or len(outputs) != 1:
                raise ValueError("Expected two inputs and one output: " + name)
            output = outputs[0]
        return inputs, output

    def data_path(self, bits, depth=0):
        """Extract."""
        bits = list(bits)
        if depth > 64:
            return {"kind": "raw", "bits": bits}
        source = self.drivers.get(tuple(bits))
        if source and self.cells[source[0]]["type"] == "$mux":
            c = self.cells[source[0]]["connections"]
            return {"kind": "mux", "cell": source[0], "select": c["S"],
                    "a": self.data_path(c["A"], depth + 1),
                    "b": self.data_path(c["B"], depth + 1)}
        if source and source[0] in self.adders:
            return {"kind": "adder", "cell": source[0], "bits": bits}
        for name in self.adders:
            _, out = self.adder_ports(name)
            v = self.cells[name]["connections"][out]
            if bits == v[:len(bits)] and len(bits) >= 2:
                return {"kind": "adder", "cell": name, "bits": bits, "truncated": len(bits) != len(v)}
        return {"kind": "raw", "bits": bits}

    @staticmethod
    def leaves(path):
        if path["kind"] == "mux":
            return NetGraph.leaves(path["a"]) + NetGraph.leaves(path["b"])
        return [path]

    def state_path(self, bits, register=None, depth=0):
        """Extract."""
        bits = list(bits)
        if depth > 64:
            return None
        for name, cell in self.registers.items():
            if register is not None and name != register:
                continue
            q = cell["connections"]["Q"]
            if len(bits) != len(q):
                continue
            for shift in range(len(q)):
                if bits == ["0"] * shift + q[:len(q) - shift]:
                    return {"kind": "state", "register": name, "shift": shift}
        source = self.drivers.get(tuple(bits))
        if source:
            c = self.cells[source[0]]
            con = c["connections"]
            if c["type"] == "$mux":
                a = self.state_path(con["A"], register, depth + 1)
                b = self.state_path(con["B"], register, depth + 1)
                if a is not None and b is not None:
                    return {"kind": "mux", "cell": source[0], "select": con["S"], "a": a, "b": b}
            if c["type"] in ("$shl", "$sshl") and all(x in ("0", "1") for x in con["B"]):
                shift = sum((x == "1") << i for i, x in enumerate(con["B"]))
                a = self.state_path(con["A"], register, depth + 1)
                if a is not None:
                    return {"kind": "shift", "shift": shift, "a": a}
        return None

    @staticmethod
    def state_sources(path):
        if path is None:
            return set()
        if path["kind"] == "state":
            return {path["register"]}
        if path["kind"] == "mux":
            return NetGraph.state_sources(path["a"]) | NetGraph.state_sources(path["b"])
        return NetGraph.state_sources(path.get("a"))

    def upstream_arithmetic(self,bits):
        pending=[list(bits)]
        visited,found=set(),[]
        while pending and len(visited)<4096:
            vector=pending.pop()
            names={self.bit_drivers[b][0] for b in vector if b in self.bit_drivers}
            for name in names-visited:
                visited.add(name)
                cell=self.cells[name]
                if name in self.registers or name in self.adders:
                    continue
                if cell['type'] in ('$add','$mul'):
                    found.append({'cell':name,'type':cell['type']})
                ports=('A','B') if cell['type'] in ('$add','$mul','$mux','$and','$or','$xor') else ('A',)
                if cell['type'] in ('$shl','$sshl'):
                    ports=('A',)
                pending += [cell['connections'][p] for p in ports if p in cell['connections']]
        return sorted(found,key=lambda x:x['cell'])


def analyze_netlist(netlist, top, certificates):
    started = time.monotonic()
    graph = NetGraph(netlist["modules"][top], certificates, netlist["modules"])
    structures, stages = [], {}
    for reg, cell in graph.registers.items():
        path = graph.data_path(cell["connections"]["D"])
        adders = sorted({p["cell"] for p in graph.leaves(path) if p["kind"] == "adder"})
        if len(adders) != 1:
            continue
        adder = adders[0]
        inputs, out = graph.adder_ports(adder)
        operands = graph.cells[adder]["connections"]
        states = [graph.state_path(operands[p]) for p in inputs]
        predecessors = set().union(*(graph.state_sources(p) for p in states))
        width = len(cell["connections"]["Q"])
        cert = graph.adders[adder]
        actual = [len(operands[p]) for p in inputs]
        certified_widths = cert.get('input_widths',[cert.get('width',width)]*2)
        valid_width = all(0 < w <= width for w in actual) and actual == certified_widths and len(operands[out]) in (width, width + 1)
        local = bool(cert.get("low_local", cert.get("low_locality", False)))
        k = cert.get("k", cert.get("k_min"))
        legal = local and valid_width and isinstance(k, int) and 0 < k < width
        reasons = []
        if not local:
            reasons.append("Adder has no low-local certificate")
        if not valid_width:
            reasons.append("Unsupported operand/register width interface")
        if not isinstance(k, int) or not (0 < k < width):
            reasons.append("EXACT_ADDER_NO_APPROXIMATE_LOW_REGION" if k == 0 else "No separable high/low state")
        stage = {"id": "stage:" + reg, "register": reg, "adder": adder,
                 "adder_type": graph.cells[adder]["type"], "width": width,
                 "operand_widths": actual, "k": k, "data_path": path,
                 "operand_paths": states, "predecessors": sorted(predecessors),
                 "rewritable": legal, "candidates": ["T_cs"] if legal else [], "reasons": reasons,
                 "location": cell.get("attributes", {}).get("src", "UNKNOWN")}
        upstream=[v for port in inputs for v in graph.upstream_arithmetic(operands[port])]
        stage['upstream_arithmetic']=upstream
        if legal and upstream:
            stage['candidates'].append('T_csf')
        stages[reg] = stage
        if reg in predecessors:
            structures.append({**stage, "kind": "ACC"})
    pipe_edges = [(p, r) for r, s in stages.items() for p in s["predecessors"] if p != r and p in stages]
    pipe_regs = {r for edge in pipe_edges for r in edge}
    for reg in sorted(pipe_regs):
        structures.append({**stages[reg], "kind": "PIPE", "pipeline_edges": [list(e) for e in pipe_edges if reg in e]})
    for reg in sorted(set(stages) - pipe_regs):
        if not any(s["register"] == reg for s in structures):
            structures.append({**stages[reg], "kind": "REGISTERED_ADDER"})
    adj = {name: set() for name in graph.adders}
    incoming = {name: set() for name in graph.adders}
    for name in graph.adders:
        inputs, _ = graph.adder_ports(name)
        for port in inputs:
            path = graph.data_path(graph.cells[name]["connections"][port])
            if path["kind"] == "adder":
                prev = path["cell"]
                if prev != name:
                    adj[prev].add(name)
                    incoming[name].add(prev)
    unseen = set(graph.adders)
    while unseen:
        root = min(unseen)
        todo, component = [root], set()
        while todo:
            node = todo.pop()
            if node in component:
                continue
            component.add(node)
            todo += list(adj[node] | incoming[node])
        unseen -= component
        if len(component) < 2:
            continue
        certificates_here = [graph.adders[x] for x in component]
        same = len({json.dumps([c.get("k", c.get("k_min")), c.get("phi"), c.get("kappa")]) for c in certificates_here}) == 1
        local = all(c.get("low_local", False) for c in certificates_here)
        associative = same and local and all(c.get("t1", {}).get("associative", False) for c in certificates_here)
        sizes=[c.get('t2',{}).get('row_quotient_m',c.get('t2',{}).get('state_count')) for c in certificates_here]
        small = same and local and all(isinstance(size,int) and 0<size<=16 for size in sizes)
        chain = all(len(incoming[n]) <= 1 and len(adj[n]) <= 1 for n in component)
        structures.append({"id": "comb:" + min(component), "kind": "CHAIN" if chain else "TREE",
                           "adders": sorted(component), "adder_types": sorted({graph.cells[n]["type"] for n in component}),
                           "edges": [[a, b] for a in sorted(component) for b in sorted(adj[a])],
                           "operand_widths": sorted({len(graph.cells[n]["connections"][p]) for n in component for p in graph.adder_ports(n)[0]}),
                           "rewritable": associative or small,
                           "candidates": (["T1"] if associative else []) + (["T2"] if small else []),
                           "reasons": [] if associative or small else ["No full-domain associativity certificate and quotient exceeds implementation limit"],
                           "t1_rejected": not associative})
    return {"schema_version": 1, "top": top, "status": "PASS", "structures": structures,
            "stages": list(stages.values()), "adder_count": len(graph.adders),
            "register_count": len(graph.registers), "elapsed_s": time.monotonic() - started}


def detect_design(sources, top, certificates, out_dir, runner=None, yosys=None):
    """Extract."""
    from .runtime import run_guarded, tool
    runner, yosys = runner or run_guarded, yosys or tool("yosys")
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [str(Path(p).resolve()) for p in sources]
    full = out / "elaborated.json"
    script = out / "elaborate.ys"
    script.write_text("\n".join(["read_verilog -sv " + " ".join(_quote(p) for p in sources),
                               "hierarchy -check -top " + top, "proc", "write_json " + _quote(full)]), encoding="utf-8")
    rec = runner([str(yosys), "-Q", "-s", str(script)], cwd=out, log=out / "elaborate.log", timeout=300)
    if rec["returncode"] or not full.exists():
        return {"status": rec.get("status", "UNKNOWN_ELABORATION"), "top": top, "structures": [], "tool": rec}
    net = json.loads(full.read_text(encoding='utf-8'))
    certs = _certs(certificates)
    matchnames = set(certs) | {c.get('match_module') for c in certs.values() if c.get('match_module')}
    known = []
    for name, mod in net["modules"].items():
        hdlname = mod.get("attributes", {}).get("hdlname", "").split()
        if name in matchnames or (hdlname and hdlname[0] in matchnames):
            known.append(name)
    graphfile = out / "graph.json"
    script = out / "detect.ys"
    lines = ["read_json " + _quote(full)] + ["blackbox " + n for n in known]
    lines += ["hierarchy -top " + top, "flatten", "opt_clean", "write_json " + _quote(graphfile)]
    script.write_text("\n".join(lines), encoding="utf-8")
    rec2 = runner([str(yosys), "-Q", "-s", str(script)], cwd=out, log=out / "detect.log", timeout=300)
    if rec2["returncode"] or not graphfile.exists():
        return {"status": rec2.get("status", "UNKNOWN_GRAPH"), "top": top, "structures": [], "tool": rec2}
    result = analyze_netlist(json.loads(graphfile.read_text(encoding='utf-8')), top, certificates)
    result.update({"graph_json": str(graphfile), "elaborated_json": str(full), "sources": sources,
                   "blackbox_modules": known, "tools": [rec, rec2]})
    (out / "DETECTION.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result

