"""Prepare one design for technology mapping without shared caches."""
from pathlib import Path
from .runtime import run_guarded, tool


def prepare(files, top, lib, heavy=False, out=None):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    net = out / 'prepared.il'
    lines = [f'read_liberty -lib {lib}',
             'read_verilog -sv ' + ' '.join(str(p) for p in files),
             f'hierarchy -check -top {top}', 'proc', 'flatten',
             f'synth -top {top} -flatten -noabc -run begin:coarse',
             f'synth -top {top} -noabc -run fine:check',
             f'dfflibmap -liberty {lib}', f'write_rtlil {net}']
    script = out / 'prepare.ys'
    script.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    execution = run_guarded([tool('yosys'), '-q', '-s', script], cwd=out,
                            log=out / 'prepare.log', timeout=1800)
    status = execution['status']
    if status == 'PASS' and not net.exists():
        status = 'UNKNOWN_FRONTEND_OUTPUT'
    return dict(status=status, execution=execution, prepared=str(net),
                frontend_reused=False)
