"""
Tests for the Management Pack Parser
"""

import pytest
from pathlib import Path

from scom_migrator.parser import ManagementPackParser
from scom_migrator.models import MonitorType, RuleType, DataSourceType


# Path to sample management pack
SAMPLE_MP_PATH = Path(__file__).parent.parent / "samples" / "Sample.Windows.Monitoring.xml"


class TestManagementPackParser:
    """Tests for ManagementPackParser."""
    
    def test_parse_sample_mp(self):
        """Test parsing the sample management pack."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert mp is not None
        assert mp.metadata.id == "Sample.Windows.Monitoring"
        assert mp.metadata.version == "1.0.0.0"
    
    def test_parse_metadata(self):
        """Test metadata extraction."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert mp.metadata.display_name == "Sample Windows Monitoring Pack"
        assert len(mp.metadata.references) >= 1
    
    def test_parse_classes(self):
        """Test class definition extraction."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert len(mp.classes) >= 2
        
        server_class = next((c for c in mp.classes if "Server" in c.id), None)
        assert server_class is not None
    
    def test_parse_monitors(self):
        """Test monitor extraction."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert len(mp.monitors) >= 5
        
        # Check CPU monitor
        cpu_monitor = next(
            (m for m in mp.monitors if "CPU" in m.id), 
            None
        )
        assert cpu_monitor is not None
        assert cpu_monitor.generates_alert is True
    
    def test_parse_rules(self):
        """Test rule extraction."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert len(mp.rules) >= 3
        
        # Check performance collection rule
        perf_rule = next(
            (r for r in mp.rules if "Collection" in r.id and "CPU" in r.id),
            None
        )
        assert perf_rule is not None
    
    def test_parse_discoveries(self):
        """Test discovery extraction."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert len(mp.discoveries) >= 2
    
    def test_is_management_pack(self):
        """Test management pack detection."""
        assert ManagementPackParser.is_management_pack(SAMPLE_MP_PATH) is True
        assert ManagementPackParser.is_management_pack(__file__) is False
    
    def test_file_not_found(self):
        """Test handling of missing file."""
        parser = ManagementPackParser("nonexistent.xml")
        
        with pytest.raises(FileNotFoundError):
            parser.parse()
    
    def test_alert_generating_items(self):
        """Test counting of alert-generating items."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        assert mp.alert_generating_items >= 4
    
    def test_data_source_identification(self):
        """Test data source type identification."""
        parser = ManagementPackParser(SAMPLE_MP_PATH)
        mp = parser.parse()
        
        # Find a performance monitor
        perf_monitor = next(
            (m for m in mp.monitors if m.data_source and "Performance" in str(m.data_source.type_id)),
            None
        )
        
        if perf_monitor and perf_monitor.data_source:
            assert perf_monitor.data_source.data_source_type in [
                DataSourceType.PERFORMANCE_COUNTER,
                DataSourceType.UNKNOWN,
            ]
