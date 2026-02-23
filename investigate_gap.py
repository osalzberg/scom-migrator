"""Investigate the 6-resource gap in Windows Server 2016 MP at the generator level."""
from src.scom_migrator.parser import ManagementPackParser
from src.scom_migrator.mapper import AzureMonitorMapper
from src.scom_migrator.analyzer import MigrationAnalyzer
from src.scom_migrator.generator import ARMTemplateGenerator
from src.scom_migrator.models import MigrationComplexity, AzureMonitorTargetType

ARM_TYPES = {AzureMonitorTargetType.LOG_ALERT, AzureMonitorTargetType.METRIC_ALERT}

parser = ManagementPackParser('/Users/orensalzberg/Downloads/Windows_Server_2016_Operating_System_Monitoring_10.0.8.0.xml')
mp = parser.parse()
mapper = AzureMonitorMapper()

# Collect mappings with ARM recs  
easy_with_arm = []
for m in mp.monitors:
    mapping = mapper.map_monitor(m)
    if mapping.migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE):
        if any(r.target_type in ARM_TYPES for r in mapping.recommendations):
            easy_with_arm.append(mapping)

for r in mp.rules:
    mapping = mapper.map_rule(r)
    if mapping.migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE):
        if any(r.target_type in ARM_TYPES for r in mapping.recommendations):
            easy_with_arm.append(mapping)

for d in mp.discoveries:
    mapping = mapper.map_discovery(d)
    if mapping.migration_complexity in (MigrationComplexity.SIMPLE, MigrationComplexity.MODERATE):
        if any(r.target_type in ARM_TYPES for r in mapping.recommendations):
            easy_with_arm.append(mapping)

print(f"Easy components with ARM recs: {len(easy_with_arm)}")

# Now check how the generator processes them
gen = ARMTemplateGenerator()

# Manually generate resources like the generator does
from src.scom_migrator.models import ARMResource
names_seen = {}
duplicates = []
for mapping in easy_with_arm:
    resources = gen._generate_resources_from_mapping(mapping, "[resourceGroup().location]")
    if not resources:
        print(f"NO RESOURCE: {mapping.source_type}: {mapping.source_name}")
    for res in resources:
        name = res.name
        if name in names_seen:
            duplicates.append((name, mapping.source_name, names_seen[name]))
        else:
            names_seen[name] = mapping.source_name

print(f"\nTotal unique ARM resources generated: {len(names_seen)}")
print(f"Duplicate names found: {len(duplicates)}")
if duplicates:
    print("\nDuplicates:")
    for name, src1, src2 in duplicates[:20]:
        print(f"  Name: {name}")
        print(f"    Component 1: {src1}")
        print(f"    Component 2: {src2}")
        print()
