"""Trace the full pipeline for Windows Server 2016 MP to find the 6-gap."""
from src.scom_migrator.parser import ManagementPackParser
from src.scom_migrator.analyzer import MigrationAnalyzer
from src.scom_migrator.generator import ARMTemplateGenerator
from src.scom_migrator.models import MigrationComplexity

parser = ManagementPackParser('/Users/orensalzberg/Downloads/Windows_Server_2016_Operating_System_Monitoring_10.0.8.0.xml')
mp = parser.parse()

analyzer = MigrationAnalyzer()
report = analyzer.analyze(mp)

print(f"Report mappings: {len(report.mappings)}")
easy = [m for m in report.mappings if m.migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE)]
print(f"Easy: {len(easy)}")

gen = ARMTemplateGenerator()

# Use generate_from_report to get "alert rules only" template  
template = gen.generate_from_report(report)
if isinstance(template, list):
    total_alerts = sum(
        sum(1 for r in t.get("resources", []) if r.get("type") in gen.ALERT_RESOURCE_TYPES)
        for t in template
    )
else:
    total_alerts = sum(1 for r in template.get("resources", []) if r.get("type") in gen.ALERT_RESOURCE_TYPES)
print(f"generate_from_report alerts: {total_alerts}")

# Use generate_complete_deployment  
complete = gen.generate_complete_deployment(report)
if isinstance(complete, list):
    total_res = sum(len(t.get("resources", [])) for t in complete)
    complete_alerts = sum(
        sum(1 for r in t.get("resources", []) if r.get("type") in gen.ALERT_RESOURCE_TYPES)
        for t in complete
    )
else:
    total_res = len(complete.get("resources", []))
    complete_alerts = sum(1 for r in complete.get("resources", []) if r.get("type") in gen.ALERT_RESOURCE_TYPES)
print(f"generate_complete_deployment: {total_res} resources, {complete_alerts} alert rules")

# Check if the issue is in the analyzer creating the report
# The analyzer creates mappings independently - let's check if its count matches
from src.scom_migrator.mapper import AzureMonitorMapper
from src.scom_migrator.models import AzureMonitorTargetType
ARM_TYPES = {AzureMonitorTargetType.LOG_ALERT, AzureMonitorTargetType.METRIC_ALERT}

mapper = AzureMonitorMapper()
manual_mappings = []
for m in mp.monitors:
    manual_mappings.append(mapper.map_monitor(m))
for r in mp.rules:
    manual_mappings.append(mapper.map_rule(r))
for d in mp.discoveries:
    manual_mappings.append(mapper.map_discovery(d))

easy_manual = [m for m in manual_mappings if m.migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE)]
easy_with_arm = [m for m in easy_manual if any(r.target_type in ARM_TYPES for r in m.recommendations)]
print(f"\nManual mapping: total={len(manual_mappings)}, easy={len(easy_manual)}, easy_with_arm={len(easy_with_arm)}")
print(f"Report mapping: total={len(report.mappings)}, easy={len(easy)}")

# Now check: report.mappings vs manual count
report_easy_arm = [m for m in easy if any(r.target_type in ARM_TYPES for r in m.recommendations)]
print(f"Report easy with ARM: {len(report_easy_arm)}")
