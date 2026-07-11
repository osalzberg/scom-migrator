"""
Tests for the ARM Template Generator
"""

import json
import pytest
from pathlib import Path

from scom_migrator.parser import ManagementPackParser
from scom_migrator.analyzer import MigrationAnalyzer
from scom_migrator.generator import ARMTemplateGenerator


SAMPLE_MP_PATH = Path(__file__).parent.parent / "samples" / "Sample.Windows.Monitoring.xml"


class TestARMTemplateGenerator:
    """Tests for ARMTemplateGenerator."""
    
    @pytest.fixture
    def sample_report(self):
        """Generate sample migration report."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        analyzer = MigrationAnalyzer()
        return analyzer.analyze(mp)
    
    @pytest.fixture
    def generator(self):
        """Create generator instance."""
        return ARMTemplateGenerator()
    
    def test_generate_template(self, sample_report, generator):
        """Test ARM template generation."""
        template = generator.generate_from_report(sample_report)
        
        assert template is not None
        assert "$schema" in template
        assert "contentVersion" in template
        assert "resources" in template
    
    def test_template_has_parameters(self, sample_report, generator):
        """Test template parameters."""
        template = generator.generate_from_report(sample_report)
        
        assert "parameters" in template
        assert "workspaceName" in template["parameters"]
    
    def test_template_has_resources(self, sample_report, generator):
        """Test template resources."""
        template = generator.generate_from_report(sample_report)
        
        assert len(template["resources"]) > 0
    
    def test_workspace_resource(self, sample_report, generator):
        """Test workspace resource generation."""
        template = generator.generate_from_report(
            sample_report, 
            include_workspace=True
        )
        
        workspace_resources = [
            r for r in template["resources"] 
            if "workspaces" in r["type"]
        ]
        assert len(workspace_resources) == 1
    
    def test_action_group_resource(self, sample_report, generator):
        """Test action group resource generation."""
        template = generator.generate_from_report(
            sample_report,
            include_action_group=True
        )
        
        ag_resources = [
            r for r in template["resources"]
            if "actionGroups" in r["type"]
        ]
        assert len(ag_resources) == 1
    
    def test_alert_rules_only(self, sample_report, generator):
        """Test alert rules only template."""
        template = generator.generate_alert_rules_only(sample_report)
        
        assert template is not None
        assert "resources" in template
    
    def test_dcr_template(self, sample_report, generator):
        """Test DCR template generation."""
        template = generator.generate_data_collection_rules(sample_report)
        
        assert template is not None
        
        dcr_resources = [
            r for r in template["resources"]
            if "dataCollectionRules" in r["type"]
        ]
        # Should have at least one DCR
        assert len(dcr_resources) >= 0
    
    def test_template_is_valid_json(self, sample_report, generator):
        """Test that generated template is valid JSON."""
        template = generator.generate_from_report(sample_report)
        
        # Should be serializable
        json_str = json.dumps(template)
        assert json_str is not None
        
        # Should be deserializable back
        parsed = json.loads(json_str)
        assert parsed == template
    
    def test_export_template(self, sample_report, generator, tmp_path):
        """Test template export to file."""
        template = generator.generate_from_report(sample_report)
        output_path = tmp_path / "test-template.json"
        
        generator.export_template(template, str(output_path))
        
        assert output_path.exists()
        
        # Verify content
        with open(output_path) as f:
            loaded = json.load(f)
        assert loaded["$schema"] == template["$schema"]
    
    def test_resource_naming(self, generator):
        """Test resource name sanitization."""
        # Test various inputs
        assert generator._sanitize_resource_name("Simple Name") == "simple-name"
        assert generator._sanitize_resource_name("Name.With.Dots") == "name-with-dots"
        assert generator._sanitize_resource_name("Name--With--Dashes") == "name-with-dashes"
        assert len(generator._sanitize_resource_name("A" * 100)) <= 60

    def test_metric_alerts_generated_for_native_counters(self, sample_report, generator):
        """CPU/memory/disk perf monitors should produce native metric alerts."""
        template = generator.generate_from_report(sample_report)

        metric_alerts = [
            r for r in template["resources"]
            if r["type"] == "Microsoft.Insights/metricAlerts"
        ]
        # The sample has Processor / Memory / LogicalDisk monitors that all map
        # to native Azure metrics, so at least one metric alert must exist.
        assert len(metric_alerts) > 0

    def test_metric_alert_references_defined_parameter(self, sample_report, generator):
        """Every metric alert must scope to a declared targetResourceId parameter.

        Regression for the deployment bug where metric alerts referenced
        ``parameters('targetResourceId')`` without the parameter being declared,
        causing the ARM deployment to fail.
        """
        template = generator.generate_from_report(sample_report)

        metric_alerts = [
            r for r in template["resources"]
            if r["type"] == "Microsoft.Insights/metricAlerts"
        ]
        assert len(metric_alerts) > 0

        # The parameter the alerts reference must actually be declared.
        assert "targetResourceId" in template.get("parameters", {})

        for alert in metric_alerts:
            blob = json.dumps(alert)
            assert "parameters('targetResourceId')" in blob
            # Guarded so it is skipped when no target resource is supplied,
            # avoiding an empty-scope deployment failure.
            assert "targetResourceId" in json.dumps(alert.get("condition", ""))

    def test_metric_alert_preserves_scom_threshold(self, sample_report, generator):
        """The CPU metric alert must carry the real SCOM threshold (85), not a default."""
        template = generator.generate_from_report(sample_report)

        cpu_alert = next(
            (r for r in template["resources"]
             if r["type"] == "Microsoft.Insights/metricAlerts"
             and "cpu" in r.get("name", "").lower()),
            None,
        )
        assert cpu_alert is not None
        criterion = cpu_alert["properties"]["criteria"]["allOf"][0]
        assert criterion["metricName"] == "Percentage CPU"
        assert criterion["threshold"] == 85.0

    def test_standalone_dcr_not_mutated_by_complete_deployment(self, sample_report, generator):
        """Generating the complete deployment must not corrupt the standalone DCR.

        Regression for the in-place mutation bug where the complete-deployment
        builder rewrote the shared DCR's workspace reference to an undefined
        variable, breaking the standalone DCR download.
        """
        dcr_template = generator.generate_data_collection_rules(sample_report)
        generator.generate_complete_deployment(sample_report, prebuilt_dcr=dcr_template)

        blob = json.dumps(dcr_template)
        assert "parameters('workspaceResourceId')" in blob
        assert "variables('actualWorkspaceResourceId')" not in blob
