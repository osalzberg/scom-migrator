"""Check what resource types the ARM template produces for Windows Server 2016 MP."""
from src.scom_migrator.parser import ManagementPackParser
from src.scom_migrator.analyzer import MigrationAnalyzer
from src.scom_migrator.generator import ARMTemplateGenerator
from collections import Counter

parser = ManagementPackParser('/Users/orensalzberg/Downloads/Windows_Server_2016_Operating_System_Monitoring_10.0.8.0.xml')
mp = parser.parse()

analyzer = MigrationAnalyzer()
report = analyzer.analyze(mp)
gen = ARMTemplateGenerator()

# Get raw ARM template (alert rules only)
raw = gen._generate_from_report_raw(report)
resources = raw.get("resources", [])

c = Counter()
for r in resources:
    c[r.get("type", "UNKNOWN")] += 1

print("Resource types in generate_from_report_raw:")
for t, count in c.most_common():
    print(f"  {t}: {count}")

# Check what generate_complete_deployment copies
complete = gen.generate_complete_deployment(report)
if isinstance(complete, list):
    all_res = []
    for t in complete:
        all_res.extend(t.get("resources", []))
else:
    all_res = complete.get("resources", [])

c2 = Counter()
for r in all_res:
    c2[r.get("type", "UNKNOWN")] += 1

print("\nResource types in generate_complete_deployment:")
for t, count in c2.most_common():
    print(f"  {t}: {count}")

# Check diff
sqr_raw = sum(1 for r in resources if r.get("type") == "Microsoft.Insights/scheduledQueryRules")
metric_raw = sum(1 for r in resources if r.get("type") == "Microsoft.Insights/metricAlerts")
print(f"\nRaw: {sqr_raw} scheduledQueryRules + {metric_raw} metricAlerts = {sqr_raw + metric_raw} total alert rules")
