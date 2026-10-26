"""Characterize, extract, recode and prove the supplied small accumulator."""
import argparse
import json
from pathlib import Path
from bear.cli import characterize_library, library_specs
from bear.extract import detect_design
from bear.reencode import rewrite_design
from bear.verify import prove

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--out', required=True)
args = p.parse_args()
out = Path(args.out).resolve()
here = Path(__file__).resolve().parent
certs = characterize_library(library_specs(here/'adders.json'), out/'certificates')
det = detect_design([here/'loa_accumulator.v'], 'loa_accumulator', certs, out/'detect')
candidate = rewrite_design(det, certs, out/'rewrite', 'T_cs')
if candidate.get('status') != 'GENERATED':
    raise SystemExit('Candidate unavailable: '+json.dumps(candidate))
proof = prove(here/'loa_accumulator.v', candidate['rtl'], 'loa_accumulator', out/'proof',
              refinement=candidate.get('refinement'), formal_engine='yosys_sat', cycles=1000)
print(json.dumps({'candidate': candidate['rtl'], 'status': proof.get('status'),
                  'scope_status': proof.get('scope_status')}))
if proof.get('status') != 'PASS' or proof.get('scope_status') != 'FULL_PREFIX':
    raise SystemExit(1)
