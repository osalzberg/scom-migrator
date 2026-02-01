"""
SCOM Management Pack XML Parser

Parses SCOM Management Pack (.xml or .mp) files and extracts all relevant
monitoring configurations including monitors, rules, discoveries, and classes.
"""

import re
from pathlib import Path
from typing import Optional, Any
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET

from .models import (
    ManagementPack,
    ManagementPackMetadata,
    SCOMClass,
    SCOMRelationship,
    SCOMMonitor,
    SCOMRule,
    SCOMDiscovery,
    SCOMDataSource,
    SCOMCondition,
    MonitorType,
    RuleType,
    DataSourceType,
    Severity,
)


class ManagementPackParser:
    """
    Parser for SCOM Management Pack XML files.
    
    Supports both sealed (.mp) and unsealed (.xml) management packs.
    """
    
    # Common SCOM XML namespaces
    NAMESPACES = {
        "mp": "http://schemas.microsoft.com/MOMv3/Manifest",
        "xsd": "http://www.w3.org/2001/XMLSchema",
        "mom": "http://schemas.microsoft.com/mom/2005",
        "sc": "http://schemas.microsoft.com/mom/2005/ManagementPack",
        "wsman": "http://schemas.microsoft.com/wbem/wsman/1/config",
    }
    
    # Data source type patterns for identification
    DATA_SOURCE_PATTERNS = {
        DataSourceType.WINDOWS_EVENT: [
            "Microsoft.Windows.EventProvider",
            "EventLog",
            "WindowsEvent",
        ],
        DataSourceType.PERFORMANCE_COUNTER: [
            "Microsoft.Windows.TimedPowerShell.PerformanceProvider",
            "PerformanceCounter",
            "Perf.Counter",
            "System.Performance",
        ],
        DataSourceType.WMI: [
            "Microsoft.Windows.WmiProvider",
            "WMI",
            "WmiQuery",
        ],
        DataSourceType.SCRIPT: [
            "Microsoft.Windows.TimedScript",
            "ScriptProvider",
            "VBScript",
            "JScript",
        ],
        DataSourceType.POWERSHELL: [
            "Microsoft.Windows.TimedPowerShell",
            "PowerShell",
            "PSScript",
        ],
        DataSourceType.LOG_FILE: [
            "Microsoft.Windows.LogFileProvider",
            "LogFile",
            "TextLog",
        ],
        DataSourceType.SNMP: [
            "Microsoft.SystemCenter.Snmp",
            "SNMP",
            "SnmpProbe",
        ],
        DataSourceType.REGISTRY: [
            "Microsoft.Windows.RegistryProvider",
            "Registry",
        ],
        DataSourceType.SERVICE: [
            "Microsoft.Windows.CheckNTServiceState",
            "ServiceMonitor",
            "NTService",
        ],
        DataSourceType.PROCESS: [
            "System.ProcessInformationProvider",
            "Microsoft.Windows.ProcessProvider",
            "ProcessMonitor",
            "ProcessInformation",
        ],
        DataSourceType.HTTP: [
            "Microsoft.SystemCenter.WebApplication",
            "HttpProbe",
            "WebRequest",
        ],
        DataSourceType.DATABASE: [
            "Microsoft.SQLServer",
            "OleDbProbe",
            "Database",
        ],
    }
    
    def __init__(self, file_path: str | Path | None = None, content: bytes | str | None = None):
        """
        Initialize the parser with a management pack file or content.
        
        Args:
            file_path: Path to the management pack XML file
            content: Raw XML content as bytes or string (for serverless environments)
        """
        self.file_path = Path(file_path) if file_path else None
        self._content = content
        self._tree: Optional[ET.ElementTree] = None
        self._root: Optional[ET.Element] = None
        self._detected_namespace: str = ""
        
        if not file_path and not content:
            raise ValueError("Either file_path or content must be provided")
    
    def parse(self) -> ManagementPack:
        """
        Parse the management pack file and return a ManagementPack object.
        
        Returns:
            ManagementPack containing all parsed components
        """
        self._load_xml()
        
        metadata = self._parse_metadata()
        classes = self._parse_classes()
        relationships = self._parse_relationships()
        monitors = self._parse_monitors()
        rules = self._parse_rules()
        discoveries = self._parse_discoveries()
        
        return ManagementPack(
            metadata=metadata,
            classes=classes,
            relationships=relationships,
            monitors=monitors,
            rules=rules,
            discoveries=discoveries,
        )
    
    def _load_xml(self) -> None:
        """Load and parse the XML file or content safely."""
        if self._content:
            # Parse from content bytes or string
            if isinstance(self._content, str):
                self._root = SafeET.fromstring(self._content)
            else:
                self._root = SafeET.fromstring(self._content)
            self._tree = ET.ElementTree(self._root)
        elif self.file_path:
            if not self.file_path.exists():
                raise FileNotFoundError(f"Management pack not found: {self.file_path}")
            
            # Use defusedxml for safe parsing
            self._tree = SafeET.parse(str(self.file_path))
            self._root = self._tree.getroot()
        else:
            raise ValueError("No file path or content provided")
        
        # Detect namespace from root element
        if self._root.tag.startswith("{"):
            self._detected_namespace = self._root.tag.split("}")[0] + "}"
        
    def _find(self, path: str, element: Optional[ET.Element] = None) -> Optional[ET.Element]:
        """Find element with namespace handling."""
        root = element if element is not None else self._root
        
        # Try with namespace first
        if self._detected_namespace:
            ns_path = "/".join(
                f"{self._detected_namespace}{p}" if p and not p.startswith("@") else p
                for p in path.split("/")
            )
            result = root.find(ns_path)
            if result is not None:
                return result
        
        # Try without namespace
        result = root.find(path)
        if result is not None:
            return result
            
        # Try with common namespace prefixes
        for prefix, uri in self.NAMESPACES.items():
            ns_path = path
            for part in path.split("/"):
                if part and not part.startswith("@") and not part.startswith("{"):
                    ns_path = ns_path.replace(part, f"{{{uri}}}{part}", 1)
            result = root.find(ns_path)
            if result is not None:
                return result
        
        return None
    
    def _findall(self, path: str, element: Optional[ET.Element] = None) -> list[ET.Element]:
        """Find all elements with namespace handling."""
        root = element if element is not None else self._root
        results = []
        
        # Try with detected namespace
        if self._detected_namespace:
            ns_path = "/".join(
                f"{self._detected_namespace}{p}" if p and not p.startswith("@") else p
                for p in path.split("/")
            )
            results = root.findall(ns_path)
            if results:
                return results
        
        # Try without namespace
        results = root.findall(path)
        if results:
            return results
        
        # Use iter to find all matching elements by local name
        target_name = path.split("/")[-1]
        results = [
            elem for elem in root.iter()
            if elem.tag.endswith(target_name) or elem.tag == target_name
        ]
        
        return results
    
    def _get_text(self, element: Optional[ET.Element], default: str = "") -> str:
        """Safely get element text."""
        if element is None:
            return default
        return element.text.strip() if element.text else default
    
    def _get_attr(self, element: Optional[ET.Element], attr: str, default: str = "") -> str:
        """Safely get element attribute."""
        if element is None:
            return default
        return element.get(attr, default)
    
    def _parse_metadata(self) -> ManagementPackMetadata:
        """Parse management pack identity and metadata."""
        # Try different paths for manifest/identity
        identity = self._find(".//Identity") or self._find(".//Manifest/Identity")
        
        mp_id = ""
        version = ""
        
        if identity is not None:
            mp_id = self._get_attr(identity, "ID") or self._get_text(
                self._find("ID", identity)
            )
            version = self._get_attr(identity, "Version") or self._get_text(
                self._find("Version", identity)
            )
        
        # Try to get ID from root if not found
        if not mp_id and self._root is not None:
            mp_id = self._get_attr(self._root, "ID", "")
        
        # Get display strings
        display_name = ""
        description = ""
        
        display_strings = self._findall(".//DisplayString")
        for ds in display_strings:
            element_id = self._get_attr(ds, "ElementID")
            if element_id == mp_id or not display_name:
                name_elem = self._find("Name", ds)
                desc_elem = self._find("Description", ds)
                if name_elem is not None:
                    display_name = self._get_text(name_elem)
                if desc_elem is not None:
                    description = self._get_text(desc_elem)
        
        # Parse references
        references = []
        ref_elements = self._findall(".//Reference")
        for ref in ref_elements:
            ref_id = self._get_attr(ref, "Alias") or self._get_text(self._find("ID", ref))
            if ref_id:
                references.append(ref_id)
        
        return ManagementPackMetadata(
            id=mp_id or self.file_path.stem,
            name=mp_id or self.file_path.stem,
            version=version or "1.0.0",
            display_name=display_name or mp_id or self.file_path.stem,
            description=description,
            references=references,
        )
    
    def _parse_classes(self) -> list[SCOMClass]:
        """Parse class type definitions."""
        classes = []
        
        # Find all class definitions
        class_elements = self._findall(".//ClassType") + self._findall(".//ClassTypes/ClassType")
        
        for elem in class_elements:
            class_id = self._get_attr(elem, "ID")
            if not class_id:
                continue
            
            # Parse properties
            properties = {}
            for prop in self._findall(".//Property", elem):
                prop_id = self._get_attr(prop, "ID")
                prop_type = self._get_attr(prop, "Type", "string")
                if prop_id:
                    properties[prop_id] = prop_type
            
            classes.append(SCOMClass(
                id=class_id,
                name=class_id,
                base_class=self._get_attr(elem, "Base", ""),
                is_abstract=self._get_attr(elem, "Abstract", "false").lower() == "true",
                is_singleton=self._get_attr(elem, "Singleton", "false").lower() == "true",
                properties=properties,
            ))
        
        return classes
    
    def _parse_relationships(self) -> list[SCOMRelationship]:
        """Parse relationship type definitions."""
        relationships = []
        
        rel_elements = self._findall(".//RelationshipType") + self._findall(".//RelationshipTypes/RelationshipType")
        
        for elem in rel_elements:
            rel_id = self._get_attr(elem, "ID")
            if not rel_id:
                continue
            
            source = self._find("Source", elem)
            target = self._find("Target", elem)
            
            relationships.append(SCOMRelationship(
                id=rel_id,
                name=rel_id,
                source_class=self._get_attr(source, "ID", "") if source is not None else "",
                target_class=self._get_attr(target, "ID", "") if target is not None else "",
                relationship_type=self._get_attr(elem, "Base", "Hosting"),
            ))
        
        return relationships
    
    def _parse_monitors(self) -> list[SCOMMonitor]:
        """Parse all monitor definitions."""
        monitors = []
        
        # Find unit monitors
        monitor_elements = (
            self._findall(".//UnitMonitor") +
            self._findall(".//AggregateMonitor") +
            self._findall(".//DependencyMonitor") +
            self._findall(".//Monitors/UnitMonitor")
        )
        
        for elem in monitor_elements:
            monitor = self._parse_single_monitor(elem)
            if monitor:
                monitors.append(monitor)
        
        return monitors
    
    def _parse_single_monitor(self, elem: ET.Element) -> Optional[SCOMMonitor]:
        """Parse a single monitor element."""
        monitor_id = self._get_attr(elem, "ID")
        if not monitor_id:
            return None
        
        # Determine monitor type from element tag
        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        monitor_type = MonitorType.UNIT_MONITOR
        if "Aggregate" in tag_name:
            monitor_type = MonitorType.AGGREGATE_MONITOR
        elif "Dependency" in tag_name:
            monitor_type = MonitorType.DEPENDENCY_MONITOR
        
        # Get target class
        target = self._get_attr(elem, "Target")
        
        # Parse configuration
        config = self._find(".//Configuration", elem)
        data_source = self._parse_data_source(elem)
        
        # Parse alert settings
        alert_settings = self._find(".//AlertSettings", elem)
        generates_alert = alert_settings is not None
        alert_severity = Severity.WARNING
        alert_message = ""
        
        if alert_settings is not None:
            severity_elem = self._find("AlertSeverity", alert_settings)
            if severity_elem is not None:
                sev_text = self._get_text(severity_elem).lower()
                if "error" in sev_text or "critical" in sev_text:
                    alert_severity = Severity.CRITICAL
                elif "info" in sev_text:
                    alert_severity = Severity.INFORMATION
            
            message_elem = self._find(".//AlertMessage", alert_settings)
            if message_elem is not None:
                alert_message = self._get_attr(message_elem, "ResourceID") or self._get_text(message_elem)
        
        # Parse thresholds from configuration - more comprehensive extraction
        threshold = None
        threshold_operator = None
        if config is not None:
            # Try multiple threshold element names
            threshold_elem = (
                self._find(".//Threshold", config) or
                self._find(".//ThresholdValue", config) or
                self._find(".//Value", config)
            )
            if threshold_elem is not None:
                try:
                    threshold = float(self._get_text(threshold_elem))
                except ValueError:
                    pass
            
            # For process monitors, look for MinProcessCount and MaxProcessCount
            if not threshold:
                min_count = self._find(".//MinProcessCount", config)
                max_count = self._find(".//MaxProcessCount", config)
                if min_count is not None:
                    try:
                        threshold = float(self._get_text(min_count))
                        threshold_operator = "GreaterEqual"
                    except ValueError:
                        pass
                elif max_count is not None:
                    try:
                        threshold = float(self._get_text(max_count))
                        threshold_operator = "LessEqual"
                    except ValueError:
                        pass
            
            # Look for direction/operator patterns
            if not threshold_operator:
                direction_elem = self._find(".//Direction", config)
                if direction_elem is not None:
                    direction = self._get_text(direction_elem).lower()
                    if "over" in direction or "greater" in direction:
                        threshold_operator = "GreaterThan"
                    elif "under" in direction or "less" in direction:
                        threshold_operator = "LessThan"
                    elif "equal" in direction:
                        threshold_operator = "Equals"
            
            # Look for explicit operator patterns
            if not threshold_operator:
                for pattern in ["GreaterThan", "LessThan", "Equals", "GreaterThanOrEqual", "LessThanOrEqual"]:
                    if self._find(f".//{pattern}", config) is not None:
                        threshold_operator = pattern
                        break
            
            # Check operator attributes
            if not threshold_operator:
                operator_attr = self._get_attr(config, "Operator")
                if operator_attr:
                    threshold_operator = operator_attr
        
        # Get display name from display strings
        display_name = self._get_display_string(monitor_id)
        
        return SCOMMonitor(
            id=monitor_id,
            name=monitor_id,
            display_name=display_name,
            target_class=target,
            monitor_type=monitor_type,
            monitor_type_id=self._get_attr(elem, "TypeID"),
            parent_monitor_id=self._get_attr(elem, "ParentMonitorID"),
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            generates_alert=generates_alert,
            alert_severity=alert_severity,
            alert_message=alert_message,
            threshold=threshold,
            threshold_operator=threshold_operator,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_rules(self) -> list[SCOMRule]:
        """Parse all rule definitions."""
        rules = []
        
        rule_elements = self._findall(".//Rule") + self._findall(".//Rules/Rule")
        
        for elem in rule_elements:
            rule = self._parse_single_rule(elem)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_single_rule(self, elem: ET.Element) -> Optional[SCOMRule]:
        """Parse a single rule element."""
        rule_id = self._get_attr(elem, "ID")
        if not rule_id:
            return None
        
        target = self._get_attr(elem, "Target")
        data_source = self._parse_data_source(elem)
        
        # Determine rule type based on content
        rule_type = self._determine_rule_type(elem, data_source)
        
        # Check for alert generation
        write_actions = self._findall(".//WriteAction", elem)
        generates_alert = any(
            "Alert" in self._get_attr(wa, "ID", "") or "Alert" in self._get_attr(wa, "TypeID", "")
            for wa in write_actions
        )
        
        # Parse alert settings if present
        alert_severity = Severity.WARNING
        alert_message = ""
        for wa in write_actions:
            if "Alert" in self._get_attr(wa, "ID", "") or "Alert" in self._get_attr(wa, "TypeID", ""):
                severity_elem = self._find(".//Severity", wa) or self._find(".//Priority", wa)
                if severity_elem is not None:
                    sev_text = self._get_text(severity_elem)
                    if sev_text in ["1", "2"] or "critical" in sev_text.lower():
                        alert_severity = Severity.CRITICAL
                    elif sev_text == "0" or "info" in sev_text.lower():
                        alert_severity = Severity.INFORMATION
        
        display_name = self._get_display_string(rule_id)
        
        return SCOMRule(
            id=rule_id,
            name=rule_id,
            display_name=display_name,
            target_class=target,
            rule_type=rule_type,
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            generates_alert=generates_alert,
            alert_severity=alert_severity,
            alert_message=alert_message,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_discoveries(self) -> list[SCOMDiscovery]:
        """Parse all discovery definitions."""
        discoveries = []
        
        discovery_elements = self._findall(".//Discovery") + self._findall(".//Discoveries/Discovery")
        
        for elem in discovery_elements:
            discovery = self._parse_single_discovery(elem)
            if discovery:
                discoveries.append(discovery)
        
        return discoveries
    
    def _parse_single_discovery(self, elem: ET.Element) -> Optional[SCOMDiscovery]:
        """Parse a single discovery element."""
        discovery_id = self._get_attr(elem, "ID")
        if not discovery_id:
            return None
        
        target = self._get_attr(elem, "Target")
        data_source = self._parse_data_source(elem)
        
        # Get discovered types
        discovered_class = ""
        discovery_types = self._findall(".//DiscoveryType", elem)
        if discovery_types:
            for dt in discovery_types:
                class_elem = self._find(".//ClassType", dt)
                if class_elem is not None:
                    discovered_class = self._get_attr(class_elem, "TypeID", "")
                    break
        
        display_name = self._get_display_string(discovery_id)
        
        return SCOMDiscovery(
            id=discovery_id,
            name=discovery_id,
            display_name=display_name,
            target_class=target,
            discovered_class=discovered_class,
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_data_source(self, parent: ET.Element) -> Optional[SCOMDataSource]:
        """Parse data source configuration from a parent element."""
        # Look for data source elements
        ds_elem = (
            self._find(".//DataSource", parent) or
            self._find(".//DataSources/DataSource", parent) or
            self._find(".//ProbeAction", parent)
        )
        
        # Also check Configuration element for inline configurations (like service monitors)
        config_elem = self._find(".//Configuration", parent)
        
        if ds_elem is None and config_elem is None:
            return None
        
        # Use config_elem if ds_elem is not found (common for unit monitors)
        source_elem = ds_elem if ds_elem is not None else config_elem
        
        ds_id = self._get_attr(source_elem, "ID", "DataSource")
        type_id = self._get_attr(parent, "TypeID", "") or self._get_attr(source_elem, "TypeID", "")
        
        # Determine data source type
        ds_type = self._identify_data_source_type(type_id, source_elem)
        
        # Parse interval
        interval = None
        interval_elem = self._find(".//IntervalSeconds", source_elem) or self._find(".//Frequency", source_elem)
        if interval_elem is not None:
            try:
                interval = int(self._get_text(interval_elem))
            except ValueError:
                pass
        
        # Parse type-specific fields
        data_source = SCOMDataSource(
            id=ds_id,
            type_id=type_id,
            data_source_type=ds_type,
            interval_seconds=interval,
        )
        
        # Windows Event specific
        log_name = self._find(".//LogName", source_elem)
        if log_name is not None:
            data_source.event_log = self._get_text(log_name)
        
        event_id = self._find(".//EventDisplayNumber", source_elem) or self._find(".//EventID", source_elem)
        if event_id is not None:
            try:
                data_source.event_id = int(self._get_text(event_id))
            except ValueError:
                pass
        
        # Event source
        event_source = self._find(".//PublisherName", source_elem) or self._find(".//Source", source_elem)
        if event_source is not None:
            data_source.event_source = self._get_text(event_source)
        
        # Performance counter specific
        for field, names in [
            ("performance_object", ["ObjectName", "Object", "CounterObject"]),
            ("performance_counter", ["CounterName", "Counter"]),
            ("performance_instance", ["InstanceName", "Instance"]),
        ]:
            for name in names:
                elem = self._find(f".//{name}", source_elem)
                if elem is not None:
                    setattr(data_source, field, self._get_text(elem))
                    break
        
        # WMI specific
        wmi_ns = self._find(".//Namespace", source_elem) or self._find(".//NameSpace", source_elem)
        if wmi_ns is not None:
            data_source.wmi_namespace = self._get_text(wmi_ns)
        
        wmi_query = self._find(".//Query", source_elem)
        if wmi_query is not None:
            data_source.wmi_query = self._get_text(wmi_query)
        
        # Script specific
        script_name = self._find(".//ScriptName", source_elem)
        if script_name is not None:
            data_source.script_name = self._get_text(script_name)
        
        script_body = self._find(".//ScriptBody", source_elem)
        if script_body is not None:
            data_source.script_body = self._get_text(script_body)
        
        # Service monitor specific - ENHANCED
        service_name = self._find(".//ServiceName", source_elem)
        if service_name is not None:
            data_source.service_name = self._get_text(service_name)
            # If we found a service name, ensure this is classified as a service monitor
            if ds_type == DataSourceType.UNKNOWN:
                data_source.data_source_type = DataSourceType.SERVICE
        
        # Process monitor specific - extract process name from Configuration
        process_name = self._find(".//ProcessName", source_elem)
        if process_name is not None:
            process_name_text = self._get_text(process_name)
            if process_name_text:
                # Store process name in service_name field for now (models.py uses this field)
                data_source.service_name = process_name_text
                # If we found a process name, ensure this is classified as a process monitor
                if ds_type == DataSourceType.UNKNOWN:
                    data_source.data_source_type = DataSourceType.PROCESS
        
        return data_source
    
    def _identify_data_source_type(self, type_id: str, elem: ET.Element) -> DataSourceType:
        """Identify the type of data source from its type ID and content."""
        type_id_lower = type_id.lower()
        elem_str = ET.tostring(elem, encoding="unicode").lower()
        
        for ds_type, patterns in self.DATA_SOURCE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in type_id_lower or pattern.lower() in elem_str:
                    return ds_type
        
        return DataSourceType.UNKNOWN
    
    def _determine_rule_type(self, elem: ET.Element, data_source: Optional[SCOMDataSource]) -> RuleType:
        """Determine the type of rule based on its configuration."""
        elem_str = ET.tostring(elem, encoding="unicode").lower()
        
        if "alert" in elem_str:
            return RuleType.ALERT_RULE
        
        if data_source:
            if data_source.data_source_type == DataSourceType.WINDOWS_EVENT:
                return RuleType.EVENT_RULE
            elif data_source.data_source_type == DataSourceType.PERFORMANCE_COUNTER:
                return RuleType.PERFORMANCE_RULE
            elif data_source.data_source_type in [DataSourceType.SCRIPT, DataSourceType.POWERSHELL]:
                return RuleType.SCRIPT_RULE
        
        # Check write actions for collection
        write_actions = self._findall(".//WriteAction", elem)
        for wa in write_actions:
            wa_type = self._get_attr(wa, "TypeID", "").lower()
            if "performance" in wa_type or "collect" in wa_type:
                return RuleType.COLLECTION_RULE
        
        return RuleType.COLLECTION_RULE
    
    def _get_display_string(self, element_id: str) -> str:
        """Get display string for an element ID."""
        display_strings = self._findall(".//DisplayString")
        for ds in display_strings:
            if self._get_attr(ds, "ElementID") == element_id:
                name_elem = self._find("Name", ds)
                if name_elem is not None:
                    return self._get_text(name_elem)
        return element_id
    
    @staticmethod
    def is_management_pack(file_path: str | Path) -> bool:
        """Check if a file appears to be a SCOM management pack."""
        path = Path(file_path)
        if not path.exists():
            return False
        
        if path.suffix.lower() not in [".xml", ".mp"]:
            return False
        
        try:
            # Quick check for MP markers
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)  # Read first 5KB
                markers = [
                    "ManagementPack",
                    "MOMv3",
                    "<Manifest>",
                    "<TypeDefinitions>",
                    "<Monitoring>",
                ]
                return any(marker in content for marker in markers)
        except Exception:
            return False
