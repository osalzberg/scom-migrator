"""
Data models for SCOM Management Pack components.

These Pydantic models represent the various elements found in SCOM Management Packs
and their Azure Monitor equivalents.
"""

from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


# ============================================================================
# Enums for classification
# ============================================================================

class MonitorType(str, Enum):
    """Types of SCOM monitors."""
    UNIT_MONITOR = "UnitMonitor"
    AGGREGATE_MONITOR = "AggregateMonitor"
    DEPENDENCY_MONITOR = "DependencyMonitor"


class RuleType(str, Enum):
    """Types of SCOM rules."""
    ALERT_RULE = "AlertRule"
    COLLECTION_RULE = "CollectionRule"
    EVENT_RULE = "EventRule"
    PERFORMANCE_RULE = "PerformanceRule"
    SCRIPT_RULE = "ScriptRule"


class DataSourceType(str, Enum):
    """Types of SCOM data sources."""
    WINDOWS_EVENT = "WindowsEvent"
    WMI = "WMI"
    PERFORMANCE_COUNTER = "PerformanceCounter"
    SCRIPT = "Script"
    LOG_FILE = "LogFile"
    SNMP = "SNMP"
    REGISTRY = "Registry"
    SERVICE = "Service"
    PROCESS = "Process"
    HTTP = "HTTP"
    DATABASE = "Database"
    POWERSHELL = "PowerShell"
    UNKNOWN = "Unknown"


class Severity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "Critical"
    WARNING = "Warning"
    INFORMATION = "Information"


class MigrationComplexity(str, Enum):
    """Complexity level for migration."""
    SIMPLE = "Simple"
    MODERATE = "Moderate"
    COMPLEX = "Complex"
    MANUAL = "ManualRequired"


class AzureMonitorTargetType(str, Enum):
    """Target Azure Monitor resource types."""
    METRIC_ALERT = "MetricAlert"
    LOG_ALERT = "LogAlert"
    ACTIVITY_LOG_ALERT = "ActivityLogAlert"
    ACTION_GROUP = "ActionGroup"
    DATA_COLLECTION_RULE = "DataCollectionRule"
    WORKBOOK = "Workbook"
    LOG_ANALYTICS_QUERY = "LogAnalyticsQuery"
    VM_INSIGHTS = "VMInsights"
    AZURE_MONITOR_AGENT = "AzureMonitorAgent"


# ============================================================================
# SCOM Component Models
# ============================================================================

class SCOMDataSource(BaseModel):
    """Represents a SCOM data source configuration."""
    id: str
    type_id: str
    data_source_type: DataSourceType = DataSourceType.UNKNOWN
    interval_seconds: Optional[int] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    
    # Specific fields for different data source types
    event_log: Optional[str] = None
    event_id: Optional[int] = None
    event_source: Optional[str] = None
    performance_object: Optional[str] = None
    performance_counter: Optional[str] = None
    performance_instance: Optional[str] = None
    wmi_namespace: Optional[str] = None
    wmi_query: Optional[str] = None
    script_name: Optional[str] = None
    script_body: Optional[str] = None
    service_name: Optional[str] = None


class SCOMCondition(BaseModel):
    """Represents a SCOM condition/expression."""
    expression_type: str
    operator: Optional[str] = None
    value: Optional[str] = None
    property_path: Optional[str] = None
    sub_expressions: list["SCOMCondition"] = Field(default_factory=list)


class SCOMMonitor(BaseModel):
    """Represents a SCOM monitor."""
    id: str
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    target_class: str
    monitor_type: MonitorType = MonitorType.UNIT_MONITOR
    monitor_type_id: Optional[str] = None
    parent_monitor_id: Optional[str] = None
    enabled: bool = True
    
    # Configuration
    data_source: Optional[SCOMDataSource] = None
    condition: Optional[SCOMCondition] = None
    
    # Alert configuration
    generates_alert: bool = False
    alert_severity: Severity = Severity.WARNING
    alert_priority: int = 1
    alert_message: Optional[str] = None
    
    # Health states
    healthy_state: Optional[str] = None
    warning_state: Optional[str] = None
    error_state: Optional[str] = None
    
    # Thresholds
    threshold: Optional[float] = None
    threshold_operator: Optional[str] = None
    
    # Raw XML for reference
    raw_xml: Optional[str] = None


class SCOMRule(BaseModel):
    """Represents a SCOM rule."""
    id: str
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    target_class: str
    rule_type: RuleType = RuleType.COLLECTION_RULE
    enabled: bool = True
    
    # Data source
    data_source: Optional[SCOMDataSource] = None
    
    # Condition
    condition: Optional[SCOMCondition] = None
    
    # Alert configuration (if alert rule)
    generates_alert: bool = False
    alert_severity: Severity = Severity.WARNING
    alert_priority: int = 1
    alert_message: Optional[str] = None
    
    # Write action (for collection rules)
    write_action_type: Optional[str] = None
    
    # Raw XML for reference
    raw_xml: Optional[str] = None


class SCOMDiscovery(BaseModel):
    """Represents a SCOM discovery."""
    id: str
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    target_class: str
    discovered_class: str
    enabled: bool = True
    
    # Data source
    data_source: Optional[SCOMDataSource] = None
    
    # Discovery method
    discovery_type: Optional[str] = None
    
    # Raw XML for reference
    raw_xml: Optional[str] = None


class SCOMClass(BaseModel):
    """Represents a SCOM class/type definition."""
    id: str
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    base_class: Optional[str] = None
    is_abstract: bool = False
    is_singleton: bool = False
    properties: dict[str, str] = Field(default_factory=dict)


class SCOMRelationship(BaseModel):
    """Represents a SCOM relationship between classes."""
    id: str
    name: str
    source_class: str
    target_class: str
    relationship_type: str


class ManagementPackMetadata(BaseModel):
    """Metadata about the management pack."""
    id: str
    name: str
    version: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    vendor: Optional[str] = None
    
    # Dependencies
    references: list[str] = Field(default_factory=list)
    
    # Categories/tags
    categories: list[str] = Field(default_factory=list)


class ManagementPack(BaseModel):
    """Complete representation of a SCOM Management Pack."""
    metadata: ManagementPackMetadata
    classes: list[SCOMClass] = Field(default_factory=list)
    relationships: list[SCOMRelationship] = Field(default_factory=list)
    monitors: list[SCOMMonitor] = Field(default_factory=list)
    rules: list[SCOMRule] = Field(default_factory=list)
    discoveries: list[SCOMDiscovery] = Field(default_factory=list)
    
    # Statistics
    @property
    def total_monitors(self) -> int:
        return len(self.monitors)
    
    @property
    def total_rules(self) -> int:
        return len(self.rules)
    
    @property
    def alert_generating_items(self) -> int:
        alert_monitors = sum(1 for m in self.monitors if m.generates_alert)
        alert_rules = sum(1 for r in self.rules if r.generates_alert)
        return alert_monitors + alert_rules


# ============================================================================
# Azure Monitor Target Models
# ============================================================================

class AzureMonitorRecommendation(BaseModel):
    """Recommendation for Azure Monitor implementation."""
    target_type: AzureMonitorTargetType
    description: str
    implementation_notes: str
    complexity: MigrationComplexity
    confidence_score: float = Field(ge=0.0, le=1.0)
    
    # Prerequisites
    prerequisites: list[str] = Field(default_factory=list)
    
    # Suggested KQL query (if applicable)
    kql_query: Optional[str] = None
    
    # ARM template snippet
    arm_template_snippet: Optional[dict[str, Any]] = None


class MigrationMapping(BaseModel):
    """Maps a SCOM component to Azure Monitor equivalent(s)."""
    source_type: str  # "Monitor", "Rule", "Discovery"
    source_id: str
    source_name: str
    source_description: Optional[str] = None
    
    # Migration details
    can_migrate: bool = True
    migration_complexity: MigrationComplexity = MigrationComplexity.MODERATE
    migration_notes: list[str] = Field(default_factory=list)
    
    # Recommendations
    recommendations: list[AzureMonitorRecommendation] = Field(default_factory=list)
    
    # Limitations
    limitations: list[str] = Field(default_factory=list)
    
    # Manual steps required
    manual_steps: list[str] = Field(default_factory=list)


class MigrationReport(BaseModel):
    """Complete migration report for a management pack."""
    management_pack: ManagementPackMetadata
    generated_at: str
    
    # Summary statistics
    total_components: int
    migratable_components: int
    requires_manual_review: int
    cannot_migrate: int
    
    # Detailed mappings
    mappings: list[MigrationMapping] = Field(default_factory=list)
    
    # Overall recommendations
    overall_recommendations: list[str] = Field(default_factory=list)
    
    # Prerequisites for migration
    prerequisites: list[str] = Field(default_factory=list)
    
    # Estimated effort
    estimated_effort_hours: Optional[float] = None


# ============================================================================
# ARM Template Models
# ============================================================================

class ARMResource(BaseModel):
    """Represents an ARM template resource."""
    type: str
    api_version: str
    name: str
    location: str = "[resourceGroup().location]"
    properties: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class ARMTemplate(BaseModel):
    """Complete ARM template."""
    schema_url: str = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    content_version: str = "1.0.0.0"
    parameters: dict[str, Any] = Field(default_factory=dict)
    variables: dict[str, Any] = Field(default_factory=dict)
    resources: list[ARMResource] = Field(default_factory=list)
    outputs: dict[str, Any] = Field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to ARM template dictionary format."""
        return {
            "$schema": self.schema_url,
            "contentVersion": self.content_version,
            "parameters": self.parameters,
            "variables": self.variables,
            "resources": [
                {
                    "type": r.type,
                    "apiVersion": r.api_version,
                    "name": r.name,
                    "location": r.location,
                    "properties": r.properties,
                    "dependsOn": r.depends_on,
                    "tags": r.tags,
                }
                for r in self.resources
            ],
            "outputs": self.outputs,
        }
