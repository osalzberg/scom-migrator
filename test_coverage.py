"""Test coverage: verify every migratable component produces an ARM resource."""
import sys
from pathlib import Path
from src.scom_migrator.parser import ManagementPackParser
from src.scom_migrator.mapper import AzureMonitorMapper
from src.scom_migrator.analyzer import MigrationAnalyzer
from src.scom_migrator.generator import ARMTemplateGenerator
from src.scom_migrator.models import MigrationComplexity, AzureMonitorTargetType

ARM_TYPES = {AzureMonitorTargetType.LOG_ALERT, AzureMonitorTargetType.METRIC_ALERT}

def test_mp(path: str) -> None:
    print(f"\n{'='*60}")
    print(f"MP: {Path(path).name}")
    print(f"{'='*60}")
    
    parser = ManagementPackParser(path)
    mp = parser.parse()
    mapper = AzureMonitorMapper()
    
    mappings = []
    for m in mp.monitors:
        mappings.append(("Monitor", m.display_name or m.name, mapper.map_monitor(m)))
    for r in mp.rules:
        mappings.append(("Rule", r.display_name or r.name, mapper.map_rule(r)))
    for d in mp.discoveries:
        mappings.append(("Discovery", d.display_name or d.name, mapper.map_discovery(d)))
    
    total = len(mappings)
    easy = [m for m in mappings if m[2].migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE)]
    manual = [m for m in mappings if m[2].migration_complexity in (MigrationComplexity.COMPLEX, MigrationComplexity.MANUAL)]
    
    # Check those without ARM-producing recs
    no_arm = []
    for stype, sname, mapping in easy:
        has = any(r.target_type in ARM_TYPES for r in mapping.recommendations)
        if not has:
            no_arm.append((stype, sname, [r.target_type.value for r in mapping.recommendations]))
    
    print(f"Total: {total}, Easy: {len(easy)}, Manual: {len(manual)}")
    print(f"Easy WITH ARM alert: {len(easy) - len(no_arm)}")
    print(f"Easy WITHOUT ARM alert: {len(no_arm)}")
    
    if no_arm:
        print("\nMISSING ARM resources:")
        for stype, sname, recs in no_arm[:10]:
            print(f"  {stype}: {sname[:60]} -> {recs}")
    
    # Generate template to verify resource count
    analyzer = MigrationAnalyzer()
    report = analyzer.analyze(mp)
    gen = ARMTemplateGenerator()
    template = gen.generate_complete_deployment(report)
    
    if isinstance(template, list):
        total_res = sum(len(t.get("resources", [])) for t in template)
        total_alerts = sum(
            sum(1 for r in t.get("resources", []) if r.get("type") in gen.ALERT_RESOURCE_TYPES)
            for t in template
        )
        print(f"\nSplit into {len(template)} batches, total resources: {total_res}, alert rules: {total_alerts}")
    else:
        res = template.get("resources", [])
        alerts = [r for r in res if r.get("type") in gen.ALERT_RESOURCE_TYPES]
        print(f"\nSingle template: {len(res)} resources, {len(alerts)} alert rules")
    
    gap = len(easy) - (total_alerts if isinstance(template, list) else len(alerts))
    if gap > 0:
        print(f"\n⚠️  GAP: {gap} easy components without alert rules!")
    else:
        print(f"\n✅ PERFECT: all {len(easy)} easy components have alert rules")
    
    return len(no_arm)


# Test all available MPs
mp_files = []
dl = Path("/Users/orensalzberg/Downloads")
for f in dl.glob("*.xml"):
    if "Microsoft" in f.name or "SCOM" in f.name or "Monitoring" in f.name:
        mp_files.append(str(f))

# Also check samples dir
samples = Path("/Users/orensalzberg/Documents/GitHub/SCOM Migrator/samples")
if samples.exists():
    for f in samples.glob("*.xml"):
        mp_files.append(str(f))

total_gaps = 0
for f in sorted(mp_files):
    try:
        gaps = test_mp(f)
        total_gaps += gaps
    except Exception as e:
        print(f"\n⚠️  Error processing {f}: {e}")

print(f"\n{'='*60}")
print(f"TOTAL MPs tested: {len(mp_files)}")
print(f"TOTAL gaps remaining: {total_gaps}")
print(f"{'='*60}")
