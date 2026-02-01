"""
Tests for the Migration Analyzer
"""

import pytest
from pathlib import Path

from scom_migrator.parser import ManagementPackParser
from scom_migrator.analyzer import MigrationAnalyzer
from scom_migrator.models import MigrationComplexity


SAMPLE_MP_PATH = Path(__file__).parent.parent / "samples" / "Sample.Windows.Monitoring.xml"


class TestMigrationAnalyzer:
    """Tests for MigrationAnalyzer."""
    
    @pytest.fixture
    def sample_mp(self):
        """Load sample management pack."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        return parser.parse()
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return MigrationAnalyzer()
    
    def test_analyze_generates_report(self, sample_mp, analyzer):
        """Test that analysis generates a report."""
        report = analyzer.analyze(sample_mp)
        
        assert report is not None
        assert report.total_components > 0
        assert report.generated_at is not None
    
    def test_report_has_mappings(self, sample_mp, analyzer):
        """Test that report contains mappings."""
        report = analyzer.analyze(sample_mp)
        
        assert len(report.mappings) > 0
        
        # Each mapping should have recommendations
        for mapping in report.mappings:
            assert mapping.source_id is not None
            assert mapping.source_type in ["Monitor", "Rule", "Discovery"]
    
    def test_report_statistics(self, sample_mp, analyzer):
        """Test report statistics calculation."""
        report = analyzer.analyze(sample_mp)
        
        # Total should match sum
        total = report.migratable_components + report.requires_manual_review + report.cannot_migrate
        assert total <= report.total_components
    
    def test_effort_estimation(self, sample_mp, analyzer):
        """Test effort estimation."""
        report = analyzer.analyze(sample_mp)
        
        assert report.estimated_effort_hours is not None
        assert report.estimated_effort_hours > 0
    
    def test_overall_recommendations(self, sample_mp, analyzer):
        """Test overall recommendations generation."""
        report = analyzer.analyze(sample_mp)
        
        assert len(report.overall_recommendations) > 0
    
    def test_prerequisites_generation(self, sample_mp, analyzer):
        """Test prerequisites list generation."""
        report = analyzer.analyze(sample_mp)
        
        assert len(report.prerequisites) > 0
        
        # Should always include basic prerequisites
        prereq_text = " ".join(report.prerequisites).lower()
        assert "azure" in prereq_text or "log analytics" in prereq_text
    
    def test_executive_summary(self, sample_mp, analyzer):
        """Test executive summary generation."""
        report = analyzer.analyze(sample_mp)
        summary = analyzer.generate_executive_summary(report)
        
        assert summary is not None
        assert len(summary) > 0
        assert "Management Pack" in summary
        assert "Summary" in summary
    
    def test_summary_stats(self, sample_mp, analyzer):
        """Test summary statistics."""
        report = analyzer.analyze(sample_mp)
        stats = analyzer.get_summary_stats(report)
        
        assert "total_components" in stats
        assert "complexity_breakdown" in stats
        assert "target_types" in stats
        assert "can_automate_percent" in stats
