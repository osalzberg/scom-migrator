"""
Migration Analyzer

Analyzes SCOM Management Packs and generates comprehensive migration reports
with recommendations for Azure Monitor implementation.
"""

from datetime import datetime, timezone
from typing import Optional

from .models import (
    ManagementPack,
    MigrationReport,
    MigrationMapping,
    MigrationComplexity,
)
from .mapper import AzureMonitorMapper


class MigrationAnalyzer:
    """
    Analyzes SCOM Management Packs and generates migration recommendations.
    
    This class coordinates the analysis of all components in a management pack
    and produces a comprehensive migration report.
    """
    
    # Effort estimates in hours per complexity level
    EFFORT_ESTIMATES = {
        MigrationComplexity.SIMPLE: 0.5,
        MigrationComplexity.MODERATE: 2.0,
        MigrationComplexity.COMPLEX: 8.0,
        MigrationComplexity.MANUAL: 16.0,
    }
    
    def __init__(self, mapper: Optional[AzureMonitorMapper] = None):
        """
        Initialize the migration analyzer.
        
        Args:
            mapper: Optional custom AzureMonitorMapper instance
        """
        self.mapper = mapper or AzureMonitorMapper()
    
    def analyze(self, management_pack: ManagementPack) -> MigrationReport:
        """
        Analyze a management pack and generate a migration report.
        
        Args:
            management_pack: The parsed management pack to analyze
            
        Returns:
            MigrationReport with detailed recommendations
        """
        mappings: list[MigrationMapping] = []
        
        # Analyze all monitors
        for monitor in management_pack.monitors:
            mapping = self.mapper.map_monitor(monitor)
            mappings.append(mapping)
        
        # Analyze all rules
        for rule in management_pack.rules:
            mapping = self.mapper.map_rule(rule)
            mappings.append(mapping)
        
        # Analyze all discoveries
        for discovery in management_pack.discoveries:
            mapping = self.mapper.map_discovery(discovery)
            mappings.append(mapping)
        
        # Calculate statistics
        total = len(mappings)
        migratable = sum(1 for m in mappings if m.can_migrate and m.migration_complexity != MigrationComplexity.MANUAL)
        manual = sum(1 for m in mappings if m.migration_complexity == MigrationComplexity.MANUAL)
        cannot = sum(1 for m in mappings if not m.can_migrate)
        
        # Calculate effort estimate
        effort = sum(
            self.EFFORT_ESTIMATES.get(m.migration_complexity, 4.0)
            for m in mappings
        )
        
        # Generate overall recommendations
        overall_recommendations = self._generate_overall_recommendations(
            management_pack, mappings
        )
        
        # Generate prerequisites
        prerequisites = self._generate_prerequisites(mappings)
        
        return MigrationReport(
            management_pack=management_pack.metadata,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_components=total,
            migratable_components=migratable,
            requires_manual_review=manual,
            cannot_migrate=cannot,
            mappings=mappings,
            overall_recommendations=overall_recommendations,
            prerequisites=prerequisites,
            estimated_effort_hours=round(effort, 1),
        )
    
    def _generate_overall_recommendations(
        self,
        mp: ManagementPack,
        mappings: list[MigrationMapping],
    ) -> list[str]:
        """Generate high-level recommendations for the migration."""
        recommendations = []
        
        # Detect unsupported features
        unsupported_features = self._detect_unsupported_features(mp, mappings)
        if unsupported_features:
            recommendations.append(
                "⚠️ **UNSUPPORTED FEATURES DETECTED**: The following SCOM features cannot be migrated automatically:"
            )
            for feature in unsupported_features:
                recommendations.append(f"   • {feature}")
            recommendations.append("")
        
        # Check complexity distribution
        complexity_counts = {}
        for m in mappings:
            complexity_counts[m.migration_complexity] = (
                complexity_counts.get(m.migration_complexity, 0) + 1
            )
        
        simple = complexity_counts.get(MigrationComplexity.SIMPLE, 0)
        moderate = complexity_counts.get(MigrationComplexity.MODERATE, 0)
        complex_count = complexity_counts.get(MigrationComplexity.COMPLEX, 0)
        manual = complexity_counts.get(MigrationComplexity.MANUAL, 0)
        
        total = len(mappings)
        
        if total == 0:
            recommendations.append(
                "⚠️ This management pack appears to be empty or contains no monitorable components."
            )
            return recommendations
        
        # Overall assessment
        simple_pct = (simple + moderate) / total * 100 if total > 0 else 0
        if simple_pct > 80:
            recommendations.append(
                f"✅ **Good migration candidate**: {simple_pct:.0f}% of components can be migrated with simple or moderate effort."
            )
        elif simple_pct > 50:
            recommendations.append(
                f"⚠️ **Moderate migration complexity**: {simple_pct:.0f}% of components can be migrated easily. "
                f"Plan additional time for the remaining {100-simple_pct:.0f}%."
            )
        else:
            recommendations.append(
                f"🔴 **Complex migration**: Only {simple_pct:.0f}% of components can be migrated easily. "
                "Consider a phased approach or custom implementation."
            )
        
        # Specific recommendations based on content
        has_perf_monitors = any(
            "performance" in str(m.recommendations).lower() 
            for m in mappings
        )
        has_event_monitors = any(
            "event" in str(m.recommendations).lower() 
            for m in mappings
        )
        has_scripts = any(
            "script" in str(m.recommendations).lower() 
            for m in mappings
        )
        
        if has_perf_monitors:
            recommendations.append(
                "📊 **Performance Monitoring**: Deploy Azure Monitor Agent with Data Collection Rules "
                "to collect performance counters. Consider using VM Insights for comprehensive VM monitoring."
            )
        
        if has_event_monitors:
            recommendations.append(
                "📋 **Event Monitoring**: Configure Windows Event collection via Data Collection Rules. "
                "Create Log Analytics scheduled query alerts for critical events."
            )
        
        if has_scripts:
            recommendations.append(
                "⚡ **Script-based Monitoring**: Review all script-based monitors carefully. "
                "Consider migrating to Azure Functions, Azure Automation, or Azure Monitor custom metrics API."
            )
        
        # Discovery recommendations
        if mp.discoveries:
            recommendations.append(
                "🔍 **Discovery**: Azure uses a different resource model than SCOM. "
                "Use Azure Resource Graph for resource discovery and VM Insights for dependency mapping."
            )
        
        # Alert recommendations
        alert_count = mp.alert_generating_items
        if alert_count > 0:
            recommendations.append(
                f"🔔 **Alerts**: {alert_count} items generate alerts. Create Action Groups in Azure Monitor "
                "to define notification targets (email, SMS, webhooks, etc.)."
            )
        
        # Architecture recommendations
        recommendations.append(
            "🏗️ **Recommended Architecture**:\n"
            "   1. Deploy Azure Monitor Agent to all target machines\n"
            "   2. Create a central Log Analytics workspace\n"
            "   3. Configure Data Collection Rules for each data type\n"
            "   4. Create alert rules and action groups\n"
            "   5. Build Azure Workbooks for visualization"
        )
        
        return recommendations
    
    def _generate_prerequisites(self, mappings: list[MigrationMapping]) -> list[str]:
        """Generate list of prerequisites for the migration."""
        prereqs = set()
        
        # Always needed
        prereqs.add("Azure subscription with appropriate permissions (Contributor or Monitoring Contributor)")
        prereqs.add("Log Analytics workspace")
        prereqs.add("Azure Monitor Agent deployed to target machines")
        
        # Check specific needs from mappings
        for mapping in mappings:
            for rec in mapping.recommendations:
                prereqs.update(rec.prerequisites)
        
        # Add common prerequisites based on content
        prereq_list = list(prereqs)
        
        # Add ordering hints
        ordered = [
            "Azure subscription with appropriate permissions (Contributor or Monitoring Contributor)",
            "Log Analytics workspace",
            "Azure Monitor Agent deployed to target machines",
        ]
        
        for p in prereq_list:
            if p not in ordered:
                ordered.append(p)
        
        return ordered
    
    def _detect_unsupported_features(
        self,
        mp: ManagementPack,
        mappings: list[MigrationMapping],
    ) -> list[str]:
        """Detect SCOM features that cannot be migrated to Azure Monitor."""
        unsupported = []
        
        # Check for aggregate monitors
        aggregate_monitors = [
            m for m in mp.monitors 
            if m.monitor_type.value == "AggregateMonitor"
        ]
        if aggregate_monitors:
            unsupported.append(
                f"Aggregate Monitors ({len(aggregate_monitors)} found) - Require custom Log Analytics queries"
            )
        
        # Check for dependency monitors
        dependency_monitors = [
            m for m in mp.monitors 
            if m.monitor_type.value == "DependencyMonitor"
        ]
        if dependency_monitors:
            unsupported.append(
                f"Dependency Monitors ({len(dependency_monitors)} found) - Use VM Insights instead"
            )
        
        # Check for script-based monitors/rules
        script_components = [
            m for m in mappings
            if any("script" in rec.description.lower() for rec in m.recommendations)
        ]
        if script_components:
            unsupported.append(
                f"Script-based Monitoring ({len(script_components)} found) - Require Azure Functions/Automation"
            )
        
        # Check for distributed applications
        if any("distributed" in c.name.lower() for c in mp.classes):
            unsupported.append(
                "Distributed Applications - No direct equivalent (use Azure Monitor Workbooks + Service Map)"
            )
        
        # Check for complex data sources
        complex_sources = []
        for monitor in mp.monitors:
            if monitor.data_source:
                if monitor.data_source.data_source_type.value in ["SNMP", "HTTP", "Database"]:
                    complex_sources.append(monitor.data_source.data_source_type.value)
        if complex_sources:
            unsupported.append(
                f"Complex Data Sources ({', '.join(set(complex_sources))}) - Require custom implementation"
            )
        
        # Check for overrides (not parsable from XML easily but mention it)
        unsupported.append(
            "Override Configurations - Must be manually recreated in Azure Monitor alert rules"
        )
        
        return unsupported
    
    def get_summary_stats(self, report: MigrationReport) -> dict:
        """
        Get summary statistics from a migration report.
        
        Args:
            report: The migration report to summarize
            
        Returns:
            Dictionary with summary statistics
        """
        complexity_breakdown = {
            "simple": 0,
            "moderate": 0,
            "complex": 0,
            "manual": 0,
        }
        
        target_types = {}
        
        for mapping in report.mappings:
            # Complexity breakdown
            if mapping.migration_complexity == MigrationComplexity.SIMPLE:
                complexity_breakdown["simple"] += 1
            elif mapping.migration_complexity == MigrationComplexity.MODERATE:
                complexity_breakdown["moderate"] += 1
            elif mapping.migration_complexity == MigrationComplexity.COMPLEX:
                complexity_breakdown["complex"] += 1
            else:
                complexity_breakdown["manual"] += 1
            
            # Target type breakdown
            for rec in mapping.recommendations:
                target = rec.target_type.value
                target_types[target] = target_types.get(target, 0) + 1
        
        return {
            "total_components": report.total_components,
            "complexity_breakdown": complexity_breakdown,
            "target_types": target_types,
            "estimated_effort_hours": report.estimated_effort_hours,
            "can_automate_percent": round(
                (complexity_breakdown["simple"] + complexity_breakdown["moderate"]) 
                / max(report.total_components, 1) * 100, 1
            ),
        }
    
    def generate_executive_summary(self, report: MigrationReport) -> str:
        """
        Generate an executive summary of the migration analysis.
        
        Args:
            report: The migration report to summarize
            
        Returns:
            Formatted executive summary string
        """
        stats = self.get_summary_stats(report)
        
        summary = f"""
# Migration Analysis Executive Summary

## Management Pack: {report.management_pack.display_name or report.management_pack.name}
**Version:** {report.management_pack.version}
**Analysis Date:** {report.generated_at}

## Summary

| Metric | Value |
|--------|-------|
| Total Components | {report.total_components} |
| Easily Migratable | {report.migratable_components} ({stats['can_automate_percent']}%) |
| Requires Manual Review | {report.requires_manual_review} |
| Cannot Migrate | {report.cannot_migrate} |
| Estimated Effort | {report.estimated_effort_hours} hours |

## Complexity Breakdown

- 🟢 Simple: {stats['complexity_breakdown']['simple']}
- 🟡 Moderate: {stats['complexity_breakdown']['moderate']}
- 🟠 Complex: {stats['complexity_breakdown']['complex']}
- 🔴 Manual: {stats['complexity_breakdown']['manual']}

## Azure Monitor Target Types

"""
        for target, count in sorted(stats['target_types'].items(), key=lambda x: -x[1]):
            summary += f"- {target}: {count}\n"
        
        summary += "\n## Key Recommendations\n\n"
        for rec in report.overall_recommendations[:5]:
            summary += f"{rec}\n\n"
        
        summary += "\n## Prerequisites\n\n"
        for prereq in report.prerequisites[:10]:
            summary += f"- {prereq}\n"
        
        return summary
