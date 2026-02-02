"""
Azure Monitor Mapper

Maps SCOM components to their Azure Monitor equivalents and generates
migration recommendations.
"""

from typing import Optional, Any

from .models import (
    SCOMMonitor,
    SCOMRule,
    SCOMDiscovery,
    SCOMDataSource,
    DataSourceType,
    MonitorType,
    RuleType,
    Severity,
    AzureMonitorTargetType,
    MigrationComplexity,
    AzureMonitorRecommendation,
    MigrationMapping,
)


class AzureMonitorMapper:
    """
    Maps SCOM monitoring components to Azure Monitor equivalents.
    
    This class analyzes SCOM monitors, rules, and discoveries and provides
    recommendations for implementing equivalent monitoring in Azure Monitor.
    """
    
    # Mapping of SCOM severity to Azure Monitor severity
    SEVERITY_MAP = {
        Severity.CRITICAL: 0,  # Sev0 - Critical
        Severity.WARNING: 2,   # Sev2 - Warning
        Severity.INFORMATION: 3,  # Sev3 - Informational
    }
    
    # Performance counter mappings to Azure Monitor metrics
    PERF_COUNTER_MAPPINGS = {
        # Processor
        ("Processor", "% Processor Time"): ("Percentage CPU", "Metric"),
        ("Processor Information", "% Processor Time"): ("Percentage CPU", "Metric"),
        # Memory
        ("Memory", "Available Bytes"): ("Available Memory Bytes", "Metric"),
        ("Memory", "Available MBytes"): ("Available Memory Bytes", "Metric"),
        ("Memory", "% Committed Bytes In Use"): ("Available Memory Bytes", "Metric"),
        ("Memory", "Pages/sec"): ("Memory\\Pages/sec", "LogAnalytics"),
        # Disk
        ("LogicalDisk", "% Free Space"): ("Logical Disk % Free Space", "Metric"),
        ("LogicalDisk", "Disk Transfers/sec"): ("Disk Transfers/sec", "Metric"),
        ("LogicalDisk", "Disk Bytes/sec"): ("Disk Bytes/sec", "Metric"),
        ("LogicalDisk", "Avg. Disk sec/Transfer"): ("Data Disk Latency", "Metric"),
        ("PhysicalDisk", "% Disk Time"): ("Data Disk IOPS", "Metric"),
        # Network
        ("Network Interface", "Bytes Total/sec"): ("Network In Total", "Metric"),
        ("Network Adapter", "Bytes Total/sec"): ("Network In Total", "Metric"),
        # SQL Server
        ("SQLServer:General Statistics", "User Connections"): None,  # Use SQL Insights
        ("SQLServer:Buffer Manager", "Buffer cache hit ratio"): None,
    }
    
    # Event log mappings to Log Analytics queries
    EVENT_LOG_MAPPINGS = {
        "Application": "Event | where EventLog == 'Application'",
        "System": "Event | where EventLog == 'System'",
        "Security": "SecurityEvent",
        "Microsoft-Windows-PowerShell/Operational": "Event | where EventLog == 'Microsoft-Windows-PowerShell/Operational'",
    }
    
    def __init__(self):
        """Initialize the Azure Monitor mapper."""
        pass
    
    def map_monitor(self, monitor: SCOMMonitor) -> MigrationMapping:
        """
        Map a SCOM monitor to Azure Monitor recommendations.
        
        Args:
            monitor: The SCOM monitor to map
            
        Returns:
            MigrationMapping with recommendations
        """
        recommendations = []
        limitations = []
        manual_steps = []
        complexity = MigrationComplexity.MODERATE
        can_migrate = True
        
        # Analyze based on monitor type and data source
        if monitor.data_source:
            ds_recommendations = self._map_data_source(
                monitor.data_source,
                monitor.threshold,
                monitor.threshold_operator,
                monitor.alert_severity,
                monitor.display_name or monitor.name,
            )
            recommendations.extend(ds_recommendations)
        
        # Handle different monitor types
        if monitor.monitor_type == MonitorType.AGGREGATE_MONITOR:
            limitations.append(
                "Aggregate monitors require custom implementation using Azure Monitor availability tests "
                "or custom Log Analytics queries"
            )
            complexity = MigrationComplexity.COMPLEX
            manual_steps.append("Create custom availability logic using Log Analytics scheduled queries")
        
        elif monitor.monitor_type == MonitorType.DEPENDENCY_MONITOR:
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.VM_INSIGHTS,
                description="Use VM Insights dependency mapping",
                implementation_notes=(
                    "Azure VM Insights provides dependency mapping through the Service Map feature. "
                    "Enable VM Insights on your VMs to automatically discover and map dependencies."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.8,
                prerequisites=[
                    "Enable VM Insights on target VMs",
                    "Install Azure Monitor Agent",
                    "Configure Log Analytics workspace",
                ],
            ))
        
        # If no recommendations yet, provide generic guidance
        if not recommendations:
            recommendations.append(self._create_generic_recommendation(monitor))
            complexity = MigrationComplexity.MANUAL
            manual_steps.append("Review monitor configuration and create equivalent Azure Monitor alert")
        
        # Check if alert generation is needed
        if monitor.generates_alert:
            notes = [
                f"Original SCOM alert severity: {monitor.alert_severity.value}",
                f"Suggested Azure Monitor severity: Sev{self.SEVERITY_MAP.get(monitor.alert_severity, 2)}",
            ]
            if monitor.alert_message:
                notes.append(f"Original alert message: {monitor.alert_message}")
            manual_steps.extend(notes)
        
        return MigrationMapping(
            source_type="Monitor",
            source_id=monitor.id,
            source_name=monitor.display_name or monitor.name,
            source_description=monitor.description,
            can_migrate=can_migrate,
            migration_complexity=complexity,
            recommendations=recommendations,
            limitations=limitations,
            manual_steps=manual_steps,
        )
    
    def map_rule(self, rule: SCOMRule) -> MigrationMapping:
        """
        Map a SCOM rule to Azure Monitor recommendations.
        
        Args:
            rule: The SCOM rule to map
            
        Returns:
            MigrationMapping with recommendations
        """
        recommendations = []
        limitations = []
        manual_steps = []
        complexity = MigrationComplexity.MODERATE
        
        # Map based on rule type
        if rule.rule_type == RuleType.PERFORMANCE_RULE:
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
                description="Create Data Collection Rule for performance metrics",
                implementation_notes=(
                    "Use Azure Monitor Data Collection Rules (DCR) to collect performance counters. "
                    "The DCR can send data to Log Analytics workspace and/or Azure Monitor Metrics."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.9,
                prerequisites=[
                    "Azure Monitor Agent installed on target machines",
                    "Log Analytics workspace configured",
                ],
                kql_query=self._generate_perf_kql(rule.data_source) if rule.data_source else None,
            ))
            complexity = MigrationComplexity.SIMPLE
            
        elif rule.rule_type == RuleType.EVENT_RULE:
            kql_query = self._generate_event_kql(rule.data_source) if rule.data_source else None
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.LOG_ALERT,
                description="Create Log Analytics alert rule for event collection",
                implementation_notes=(
                    "Configure event collection via Data Collection Rule and create a "
                    "scheduled query alert rule in Azure Monitor."
                ),
                complexity=MigrationComplexity.MODERATE,
                confidence_score=0.85,
                prerequisites=[
                    "Azure Monitor Agent with event collection DCR",
                    "Log Analytics workspace",
                ],
                kql_query=kql_query,
            ))
            
        elif rule.rule_type == RuleType.ALERT_RULE:
            if rule.data_source:
                ds_recommendations = self._map_data_source(
                    rule.data_source,
                    threshold=None,
                    threshold_operator=None,
                    severity=rule.alert_severity,
                    name=rule.display_name or rule.name,
                )
                recommendations.extend(ds_recommendations)
            else:
                recommendations.append(AzureMonitorRecommendation(
                    target_type=AzureMonitorTargetType.LOG_ALERT,
                    description="Create scheduled query alert rule",
                    implementation_notes=(
                        "Create a Log Analytics scheduled query alert to replicate this alert rule."
                    ),
                    complexity=MigrationComplexity.MODERATE,
                    confidence_score=0.7,
                ))
                
        elif rule.rule_type == RuleType.SCRIPT_RULE:
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
                description="Convert script to Azure Monitor custom data collection",
                implementation_notes=(
                    "Script-based rules can be migrated using:\n"
                    "1. Azure Functions with custom metrics API\n"
                    "2. Azure Automation runbooks\n"
                    "3. Custom text log collection via DCR\n"
                    "4. Azure Monitor Agent custom data collection"
                ),
                complexity=MigrationComplexity.COMPLEX,
                confidence_score=0.5,
                prerequisites=[
                    "Review and convert script logic",
                    "Determine appropriate Azure service for script execution",
                ],
            ))
            complexity = MigrationComplexity.COMPLEX
            manual_steps.append("Review original script and convert to Azure Function or Automation Runbook")
            if rule.data_source and rule.data_source.script_body:
                manual_steps.append("Script content available in raw_xml for reference")
        
        return MigrationMapping(
            source_type="Rule",
            source_id=rule.id,
            source_name=rule.display_name or rule.name,
            source_description=rule.description,
            can_migrate=True,
            migration_complexity=complexity,
            recommendations=recommendations,
            limitations=limitations,
            manual_steps=manual_steps,
        )
    
    def map_discovery(self, discovery: SCOMDiscovery) -> MigrationMapping:
        """
        Map a SCOM discovery to Azure Monitor recommendations.
        
        Args:
            discovery: The SCOM discovery to map
            
        Returns:
            MigrationMapping with recommendations
        """
        recommendations = []
        limitations = []
        manual_steps = []
        complexity = MigrationComplexity.MODERATE
        
        # Determine discovery type and provide specific guidance
        if discovery.data_source:
            ds_type = discovery.data_source.data_source_type
            
            if ds_type == DataSourceType.WMI:
                recommendations.append(AzureMonitorRecommendation(
                    target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
                    description="Use Azure Monitor Agent with WMI data collection",
                    implementation_notes=(
                        "**How to migrate WMI-based discovery to Azure:**\n\n"
                        "1. **Create a Data Collection Rule (DCR)** with WMI data source\n"
                        "2. **Configure the WMI query** in the DCR to collect the same data\n"
                        "3. **Send data to Log Analytics** custom table\n"
                        "4. **Use KQL queries** to analyze discovered resources\n\n"
                        f"Original WMI Query: `{discovery.data_source.wmi_query or 'Not specified'}`\n"
                        f"WMI Namespace: `{discovery.data_source.wmi_namespace or 'root\\\\cimv2'}`"
                    ),
                    complexity=MigrationComplexity.MODERATE,
                    confidence_score=0.75,
                    prerequisites=[
                        "Azure Monitor Agent installed on target machines",
                        "Log Analytics workspace with custom table",
                        "Data Collection Rule with WMI data source",
                    ],
                    kql_query=self._generate_discovery_kql(discovery),
                ))
                complexity = MigrationComplexity.MODERATE
                
            elif ds_type == DataSourceType.REGISTRY:
                recommendations.append(AzureMonitorRecommendation(
                    target_type=AzureMonitorTargetType.LOG_ALERT,
                    description="Use Change Tracking and Inventory for registry-based discovery",
                    implementation_notes=(
                        "**How to migrate Registry-based discovery to Azure:**\n\n"
                        "1. **Enable Change Tracking and Inventory** solution in your Log Analytics workspace\n"
                        "2. **Configure Registry tracking** in the Change Tracking settings\n"
                        "3. **Add the specific registry paths** you want to monitor\n"
                        "4. **Query ConfigurationData** table for inventory data\n\n"
                        "**Azure Portal Steps:**\n"
                        "- Go to Automation Account → Change tracking → Edit Settings\n"
                        "- Under Windows Registry, add the registry keys to track\n"
                        "- Set collection frequency (recommended: every 1-6 hours)"
                    ),
                    complexity=MigrationComplexity.SIMPLE,
                    confidence_score=0.85,
                    prerequisites=[
                        "Azure Automation Account",
                        "Change Tracking and Inventory solution enabled",
                        "Log Analytics workspace",
                    ],
                    kql_query="""// Query registry inventory data
ConfigurationData
| where ConfigDataType == "Registry"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, RegistryKey, ValueName, ValueData
| order by TimeGenerated desc""",
                ))
                complexity = MigrationComplexity.SIMPLE
                
            elif ds_type in [DataSourceType.SCRIPT, DataSourceType.POWERSHELL]:
                recommendations.append(AzureMonitorRecommendation(
                    target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
                    description="Convert script-based discovery to Azure Automation or custom data collection",
                    implementation_notes=(
                        "**How to migrate Script-based discovery to Azure:**\n\n"
                        "**Option 1: Azure Automation Runbook (Recommended)**\n"
                        "1. Create an Azure Automation Account\n"
                        "2. Convert the discovery script to a PowerShell Runbook\n"
                        "3. Schedule the runbook to run periodically\n"
                        "4. Write results to Log Analytics using `Send-AzMonitorCustomLog`\n\n"
                        "**Option 2: Azure Functions**\n"
                        "1. Create an Azure Function with Timer trigger\n"
                        "2. Run discovery logic and push to Log Analytics\n\n"
                        "**Option 3: Custom Text Logs**\n"
                        "1. Modify script to write results to a log file\n"
                        "2. Configure DCR to collect the custom log file\n\n"
                        f"Script name: `{discovery.data_source.script_name or 'Embedded script'}`"
                    ),
                    complexity=MigrationComplexity.COMPLEX,
                    confidence_score=0.5,
                    prerequisites=[
                        "Review and convert original script logic",
                        "Azure Automation Account or Azure Functions",
                        "Log Analytics workspace",
                    ],
                ))
                complexity = MigrationComplexity.COMPLEX
                manual_steps.append("Convert discovery script to Azure Automation Runbook or Azure Function")
        
        # Always provide Azure Resource Graph recommendation for resource discovery
        recommendations.append(AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.LOG_ANALYTICS_QUERY,
            description="Use Azure Resource Graph for Azure resource discovery",
            implementation_notes=(
                "**Azure Resource Graph - For Azure Resources:**\n\n"
                "Azure Resource Graph provides instant discovery of all Azure resources.\n\n"
                "**Example queries:**\n"
                "```\n"
                "// Find all VMs\n"
                "Resources | where type == 'microsoft.compute/virtualmachines'\n\n"
                "// Find VMs by tag\n"
                "Resources | where type == 'microsoft.compute/virtualmachines' | where tags.Environment == 'Production'\n"
                "```\n\n"
                "**How to use:**\n"
                "1. Go to Azure Portal → Resource Graph Explorer\n"
                "2. Run queries to discover resources\n"
                "3. Export results or create dashboards"
            ),
            complexity=MigrationComplexity.SIMPLE,
            confidence_score=0.9,
            prerequisites=[
                "Azure subscription with Reader access",
            ],
            kql_query="""// Azure Resource Graph query - run in Resource Graph Explorer
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| project name, resourceGroup, location, properties.hardwareProfile.vmSize
| order by name""",
        ))
        
        # VM Insights for dependency discovery
        recommendations.append(AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.VM_INSIGHTS,
            description="Use VM Insights for automatic VM discovery and dependency mapping",
            implementation_notes=(
                "**VM Insights - For automatic discovery and dependency mapping:**\n\n"
                "VM Insights automatically discovers:\n"
                "- Running processes on VMs\n"
                "- Network connections between machines\n"
                "- Application dependencies\n"
                "- Performance data\n\n"
                "**How to enable VM Insights:**\n"
                "1. Go to Azure Portal → Monitor → Virtual Machines\n"
                "2. Select your VMs and click 'Enable' under Insights\n"
                "3. Choose your Log Analytics workspace\n"
                "4. Install Azure Monitor Agent\n\n"
                "**For hybrid/on-premises servers:**\n"
                "1. Enable Azure Arc on your servers first\n"
                "2. Then enable VM Insights on the Arc-enabled servers\n\n"
                "**Cost Optimization:**\n"
                "Consider using Basic or Auxiliary logs for high-volume data that doesn't need\n"
                "real-time alerting to reduce ingestion costs."
            ),
            complexity=MigrationComplexity.SIMPLE,
            confidence_score=0.85,
            prerequisites=[
                "Log Analytics workspace",
                "Azure Monitor Agent on target VMs",
                "For on-premises: Azure Arc enabled servers",
            ],
            kql_query="""// Query discovered processes from VM Insights
VMProcess
| where TimeGenerated > ago(1h)
| summarize by Computer, ExecutableName, DisplayName
| order by Computer, ExecutableName

// Query network connections/dependencies
VMConnection
| where TimeGenerated > ago(1h)
| summarize ConnectionCount=count() by SourceIp, DestinationIp, DestinationPort
| order by ConnectionCount desc""",
        ))
        
        # Change Tracking for software inventory
        recommendations.append(AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.LOG_ANALYTICS_QUERY,
            description="Use Change Tracking for software and service inventory",
            implementation_notes=(
                "**Change Tracking and Inventory - For software/service discovery:**\n\n"
                "Change Tracking automatically collects:\n"
                "- Installed software and versions\n"
                "- Windows Services and their state\n"
                "- Windows Registry keys\n"
                "- Linux daemons\n"
                "- File changes\n\n"
                "**How to enable:**\n"
                "1. Create an Azure Automation Account\n"
                "2. Go to Automation Account → Change tracking\n"
                "3. Add machines (Azure VMs or Arc-enabled servers)\n"
                "4. Configure what to track in Settings\n\n"
                "**Query inventory data:**\n"
                "Use the ConfigurationData and ConfigurationChange tables"
            ),
            complexity=MigrationComplexity.SIMPLE,
            confidence_score=0.8,
            prerequisites=[
                "Azure Automation Account",
                "Log Analytics workspace",
                "Change Tracking solution enabled",
            ],
            kql_query="""// Software inventory
ConfigurationData
| where ConfigDataType == "Software"
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by SoftwareName, Computer
| project Computer, SoftwareName, CurrentVersion, Publisher

// Windows Services inventory
ConfigurationData
| where ConfigDataType == "WindowsServices"
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by SvcName, Computer
| project Computer, SvcName, SvcDisplayName, SvcState, SvcStartupType""",
        ))
        
        limitations.append(
            "SCOM discoveries populate the SCOM database with discovered objects. "
            "Azure uses Log Analytics tables instead - query these tables to get equivalent data."
        )
        
        manual_steps.extend([
            "1. Identify what resources the SCOM discovery was finding",
            "2. Choose the appropriate Azure service (Resource Graph, VM Insights, or Change Tracking)",
            "3. Enable the service and configure data collection",
            "4. Create KQL queries to retrieve the discovered data",
            "5. Optionally create Azure Workbooks to visualize the inventory",
        ])
        
        return MigrationMapping(
            source_type="Discovery",
            source_id=discovery.id,
            source_name=discovery.display_name or discovery.name,
            source_description=discovery.description,
            can_migrate=True,
            migration_complexity=complexity,
            recommendations=recommendations,
            limitations=limitations,
            manual_steps=manual_steps,
            migration_notes=[
                "Azure provides multiple discovery mechanisms depending on what you need to discover",
                "For Azure resources: Use Azure Resource Graph",
                "For VM processes/dependencies: Use VM Insights",
                "For software/services inventory: Use Change Tracking and Inventory",
                "For custom discovery: Use Azure Automation or Azure Functions",
            ],
        )
    
    def _generate_discovery_kql(self, discovery: SCOMDiscovery) -> str:
        """Generate KQL query for discovery data."""
        if discovery.data_source and discovery.data_source.wmi_query:
            return f"""// Custom table for WMI discovery data
// Original WMI: {discovery.data_source.wmi_query}

CustomDiscovery_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, DiscoveredProperties
| order by TimeGenerated desc

// Alternative: Use VM Insights for process discovery
VMProcess
| where TimeGenerated > ago(1h)
| summarize by Computer, ExecutableName, DisplayName"""
        
        return """// Query discovered resources
// Use Azure Resource Graph for Azure resources:
// Resources | where type =~ 'microsoft.compute/virtualmachines'

// Use VM Insights for process/connection discovery:
VMProcess
| where TimeGenerated > ago(1h)
| summarize by Computer, ExecutableName

// Use Change Tracking for software inventory:
ConfigurationData
| where ConfigDataType == "Software"
| summarize arg_max(TimeGenerated, *) by SoftwareName, Computer"""
    
    def _map_data_source(
        self,
        data_source: SCOMDataSource,
        threshold: Optional[float],
        threshold_operator: Optional[str],
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map a SCOM data source to Azure Monitor recommendations."""
        recommendations = []
        
        if data_source.data_source_type == DataSourceType.PERFORMANCE_COUNTER:
            recommendations.extend(
                self._map_performance_counter(data_source, threshold, threshold_operator, severity, name)
            )
            
        elif data_source.data_source_type == DataSourceType.WINDOWS_EVENT:
            recommendations.extend(
                self._map_windows_event(data_source, severity, name)
            )
            
        elif data_source.data_source_type == DataSourceType.WMI:
            recommendations.extend(
                self._map_wmi_source(data_source, threshold, threshold_operator, severity, name)
            )
            
        elif data_source.data_source_type in [DataSourceType.SCRIPT, DataSourceType.POWERSHELL]:
            recommendations.extend(
                self._map_script_source(data_source, name)
            )
            
        elif data_source.data_source_type == DataSourceType.SERVICE:
            recommendations.extend(
                self._map_service_monitor(data_source, severity, name)
            )
            
        elif data_source.data_source_type == DataSourceType.PROCESS:
            recommendations.extend(
                self._map_process_monitor(data_source, severity, name)
            )
            
        elif data_source.data_source_type == DataSourceType.LOG_FILE:
            recommendations.extend(
                self._map_log_file_source(data_source, severity, name)
            )
            
        elif data_source.data_source_type == DataSourceType.HTTP:
            recommendations.extend(
                self._map_http_source(data_source, severity, name)
            )
        
        return recommendations
    
    def _map_performance_counter(
        self,
        data_source: SCOMDataSource,
        threshold: Optional[float],
        threshold_operator: Optional[str],
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map performance counter to Azure Monitor metric alert."""
        recommendations = []
        
        obj = data_source.performance_object or ""
        counter = data_source.performance_counter or ""
        
        # Check if there's a direct metric mapping
        mapping_key = (obj, counter)
        metric_mapping = self.PERF_COUNTER_MAPPINGS.get(mapping_key)
        
        if metric_mapping and metric_mapping[1] == "Metric":
            # Direct metric alert possible
            azure_metric, _ = metric_mapping
            
            operator_map = {
                "GreaterThan": "GreaterThan",
                "LessThan": "LessThan",
                "GreaterThanOrEqual": "GreaterThanOrEqual",
                "LessThanOrEqual": "LessThanOrEqual",
                "Equals": "Equals",
            }
            
            arm_snippet = {
                "type": "Microsoft.Insights/metricAlerts",
                "apiVersion": "2018-03-01",
                "properties": {
                    "severity": self.SEVERITY_MAP.get(severity, 2),
                    "criteria": {
                        "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                        "allOf": [{
                            "criterionType": "StaticThresholdCriterion",
                            "metricName": azure_metric,
                            "operator": operator_map.get(threshold_operator or "GreaterThan", "GreaterThan"),
                            "threshold": threshold or 90,
                            "timeAggregation": "Average",
                        }]
                    }
                }
            }
            
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.METRIC_ALERT,
                description=f"Create metric alert for {azure_metric}",
                implementation_notes=(
                    f"The SCOM performance counter '{obj}\\{counter}' maps to "
                    f"Azure Monitor metric '{azure_metric}'. Create a metric alert rule "
                    "with the appropriate threshold."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.95,
                arm_template_snippet=arm_snippet,
            ))
        else:
            # Need Log Analytics for this counter
            kql_query = self._generate_perf_kql(data_source)
            
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.LOG_ALERT,
                description=f"Create log alert for performance counter {obj}\\{counter}",
                implementation_notes=(
                    f"This performance counter requires collection via Data Collection Rule "
                    f"and a Log Analytics scheduled query alert."
                ),
                complexity=MigrationComplexity.MODERATE,
                confidence_score=0.8,
                prerequisites=[
                    "Configure DCR to collect this performance counter",
                    "Performance data flows to Log Analytics workspace",
                ],
                kql_query=kql_query,
            ))
        
        return recommendations
    
    def _map_windows_event(
        self,
        data_source: SCOMDataSource,
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map Windows event monitoring to Log Analytics alert."""
        kql_query = self._generate_event_kql(data_source)
        
        return [AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.LOG_ALERT,
            description=f"Create log alert for Windows events",
            implementation_notes=(
                f"Configure event collection via Data Collection Rule for the "
                f"'{data_source.event_log or 'Windows'}' event log, then create "
                f"a scheduled query alert rule."
            ),
            complexity=MigrationComplexity.SIMPLE,
            confidence_score=0.9,
            prerequisites=[
                "Configure DCR for Windows event collection",
                "Specify event log and event IDs to collect",
            ],
            kql_query=kql_query,
            arm_template_snippet={
                "type": "Microsoft.Insights/scheduledQueryRules",
                "apiVersion": "2022-06-15",
                "properties": {
                    "severity": self.SEVERITY_MAP.get(severity, 2),
                    "criteria": {
                        "allOf": [{
                            "query": kql_query,
                            "timeAggregation": "Count",
                            "operator": "GreaterThan",
                            "threshold": 0,
                        }]
                    }
                }
            },
        )]
    
    def _map_wmi_source(
        self,
        data_source: SCOMDataSource,
        threshold: Optional[float],
        threshold_operator: Optional[str],
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map WMI-based monitoring to Azure Monitor."""
        kql_query = self._generate_wmi_kql(data_source)
        
        return [AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.LOG_ALERT,
            description="Convert WMI query to Log Analytics",
            implementation_notes=(
                f"WMI queries can be collected using Azure Monitor Agent's WMI data source. "
                f"Original WMI query: {data_source.wmi_query or 'Not specified'}"
            ),
            complexity=MigrationComplexity.MODERATE,
            confidence_score=0.7,
            prerequisites=[
                "Configure Azure Monitor Agent with WMI data collection",
                "May require custom data collection endpoint",
            ],
            kql_query=kql_query,
        )]
    
    def _map_script_source(
        self,
        data_source: SCOMDataSource,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map script-based monitoring to Azure services."""
        recommendations = []
        
        recommendations.append(AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
            description="Convert script to Azure automation or custom metrics",
            implementation_notes=(
                "Script-based monitors have several migration paths:\n"
                "1. **Azure Functions**: Run script logic and push custom metrics\n"
                "2. **Azure Automation**: Schedule runbooks for periodic checks\n"
                "3. **Azure Monitor Agent with DCR**: Custom text log collection\n"
                "4. **Azure Monitor custom metrics API**: Push metrics from any source\n\n"
                f"Script name: {data_source.script_name or 'Embedded script'}\n\n"
                "**Cost Optimization:**\n"
                "Use Basic logs for script output data that doesn't require real-time alerting."
            ),
            complexity=MigrationComplexity.COMPLEX,
            confidence_score=0.5,
            prerequisites=[
                "Analyze script logic and dependencies",
                "Choose appropriate Azure service for execution",
                "Set up authentication and connectivity",
            ],
        ))
        
        return recommendations
    
    def _map_service_monitor(
        self,
        data_source: SCOMDataSource,
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map Windows service monitoring to Azure Monitor."""
        service_name = data_source.service_name or "YourServiceName"
        
        # Generate specific KQL query with the actual service name
        kql_query_change_tracking = f"""// Monitor {service_name} service state changes
ConfigurationChange
| where ConfigChangeType == "WindowsServices"
| where SvcName == "{service_name}"
| where SvcState == "Stopped"
| where SvcPreviousState == "Running"
| project TimeGenerated, Computer, SvcName, SvcDisplayName, SvcState, SvcStartupType
| order by TimeGenerated desc"""

        kql_query_event_log = f"""// Monitor {service_name} service via Event Log (Event ID 7036)
Event
| where EventLog == "System"
| where Source == "Service Control Manager"
| where EventID == 7036
| where RenderedDescription contains "{service_name}"
| where RenderedDescription contains "stopped"
| project TimeGenerated, Computer, RenderedDescription, EventID
| order by TimeGenerated desc"""

        kql_query_vm_process = f"""// Monitor {service_name} service process
VMProcess
| where TimeGenerated > ago(5m)
| where ProcessName contains "{service_name}"
| summarize ServiceInstances = dcount(Computer) by bin(TimeGenerated, 5m)
| where ServiceInstances == 0  // Alert when no instances found"""

        # Build implementation notes with service-specific details
        implementation_notes = f"""**Monitor Windows Service: {service_name}**

**Targeting Specific Machines (SCOM Class Equivalent):**
In SCOM, this monitor targets a specific class discovered by your discovery rule.
In Azure Monitor, use these approaches to target equivalent machines:

**Option A: Resource Tags** (Recommended)
- Tag VMs with key-value pairs matching your SCOM class
- Example: Tag="ServerRole:WebServer" or Tag="ServiceType:{service_name}"
- Alert scope: Filter by resource tags in alert rule

**Option B: Resource Groups**
- Place similar servers in same Resource Group
- Alert scope: Select specific Resource Group

**Option C: Data Collection Rules with Resource Targeting**
- Create DCRs that target specific resources using Azure Resource Manager scopes
- Use DCR associations to dynamically target VMs based on tags or resource groups
- Example: Associate DCR with all VMs tagged 'Role=WebServer'

**Migration Steps:**

**Step 1: Change Tracking (Recommended)**
1. Enable Change Tracking in Log Analytics workspace
2. Go to Automation Account → Change tracking → Edit Settings
3. Under Windows Services, add "{service_name}" to track
4. Add target machines (with appropriate tags/resource groups)

**Step 2: Create Alert with Targeting**
1. Go to Azure Portal → Monitor → Alerts → + Create → Alert rule
2. **Scope**: Select Log Analytics workspace
3. **Condition**: Custom log search with KQL query (provided below)
4. **Modify KQL to target specific machines:**
   ```
   // Add computer filtering to match your SCOM target class
   ConfigurationChange
   | where ConfigChangeType == "WindowsServices"
   | where SvcName == "{service_name}"
   | where SvcState == "Stopped"
   // TARGET FILTERING - Choose one:
   | where Computer has "webserver"  // Filter by hostname pattern
   // OR join with Heartbeat for tag-based filtering:
   | join (Heartbeat | where Tags contains "Role=WebServer") on Computer
   ```
5. Set alert severity (e.g., Sev0 for Critical)
6. Create/select Action Group for notifications

**Step 3: Test the Alert**
1. Verify data collection for target machines
2. Query to see tracked services
3. Stop service on a target machine to test alert
"""

        recommendations = [
            AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.LOG_ALERT,
                description=f"Monitor {service_name} service via Change Tracking",
                implementation_notes=implementation_notes,
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.9,
                prerequisites=[
                    "Azure Automation Account",
                    "Enable Change Tracking and Inventory solution",
                    f"Configure tracking for {service_name} service",
                    "Log Analytics workspace",
                ],
                kql_query=kql_query_change_tracking,
            ),
            AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
                description=f"Monitor {service_name} via System Event Log (Event ID 7036)",
                implementation_notes=(
                    f"**Alternative approach using Windows Event Logs:**\n\n"
                    f"Collect Service Control Manager events (Event ID 7036) that track all service state changes.\n"
                    f"Filter for '{service_name}' service specifically in your alert query.\n\n"
                    f"**DCR Configuration:**\n"
                    f"- Event Log: System\n"
                    f"- Event IDs: 7036 (Service state change)\n"
                    f"- Source: Service Control Manager\n\n"
                    f"This method provides real-time service monitoring without Change Tracking dependency."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.85,
                prerequisites=[
                    "Azure Monitor Agent on target machines",
                    "Data Collection Rule for System event log",
                    "Log Analytics workspace",
                ],
                kql_query=kql_query_event_log,
            ),
        ]
        
        # Only add VM Insights option if service name is known
        if data_source.service_name:
            recommendations.append(AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.VM_INSIGHTS,
                description=f"Monitor {service_name} service process via VM Insights",
                implementation_notes=(
                    f"**VM Insights process monitoring for {service_name}:**\n\n"
                    f"**Step-by-Step Setup:**\n\n"
                    f"1. **Enable VM Insights:**\n"
                    f"   - Go to Azure Portal → Monitor → Virtual Machines\n"
                    f"   - Select your VM(s) → Click 'Enable' under Insights tab\n"
                    f"   - Choose Log Analytics workspace\n"
                    f"   - Install Azure Monitor Agent\n\n"
                    f"2. **Wait for data collection** (5-10 minutes after enabling)\n\n"
                    f"3. **Create Log Analytics Alert:**\n"
                    f"   - Go to Azure Portal → Monitor → Alerts → + Create → Alert rule\n"
                    f"   - Select Scope: Your Log Analytics workspace\n"
                    f"   - Condition: Custom log search\n"
                    f"   - Paste the KQL query provided\n"
                    f"   - Set threshold: Greater than 0\n"
                    f"   - Evaluation frequency: Every 5 minutes\n"
                    f"   - Create/select Action Group for notifications\n\n"
                    f"4. **Test the alert:**\n"
                    f"   - Query VMProcess table to verify data is flowing\n"
                    f"   - Optionally stop the {service_name} service to trigger alert\n\n"
                    f"**Cost Optimization:**\n"
                    f"Consider using Basic logs for VMProcess data if you don't need real-time alerting."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.75,
                prerequisites=[
                    "VM Insights enabled on target machines",
                    "Azure Monitor Agent installed",
                    "Log Analytics workspace",
                ],
                kql_query=kql_query_vm_process,
            ))
        
        return recommendations
    
    def _map_process_monitor(
        self,
        data_source: SCOMDataSource,
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map Windows process monitoring to Azure Monitor - Same as service monitoring."""
        process_name = name.split()[-1] if name else "YourProcess.exe"
        
        # Generate KQL query for process monitoring
        kql_query = f"""// Monitor {process_name} process
VMProcess
| where TimeGenerated > ago(5m)
| where ExecutableName =~ "{process_name}" or ProcessName =~ "{process_name}"
| summarize ProcessCount = dcount(Computer) by bin(TimeGenerated, 5m)
| where ProcessCount == 0  // Alert when process not found on any machine
| project TimeGenerated, ProcessCount"""

        implementation_notes = f"""**Monitor Process: {process_name}**

**Process monitoring in Azure Monitor works exactly like service monitoring!**

**Targeting Specific Machines (SCOM Class Equivalent):**
Use the same targeting approaches as service monitors:

**Option A: Resource Tags** (Recommended)
- Tag VMs with key-value pairs matching your SCOM class
- Example: Tag="ServerRole:AppServer" or Tag="ProcessType:{process_name}"
- Alert scope: Filter by resource tags in alert rule

**Option B: Resource Groups**
- Place similar servers in same Resource Group
- Alert scope: Select specific Resource Group

**Option C: Data Collection Rules with Resource Targeting**
- Create DCRs that target specific resources using Azure Resource Manager scopes
- Use DCR associations to dynamically target VMs based on tags or resource groups

**Migration Steps:**

**Step 1: Enable VM Insights**
1. Go to Azure Portal → Monitor → Virtual Machines
2. Select your VM(s) → Click 'Enable' under Insights tab
3. Choose Log Analytics workspace
4. Install Azure Monitor Agent

**Step 2: Wait for Data Collection**
- Initial data collection takes 5-10 minutes
- VM Insights automatically discovers ALL running processes

**Step 3: Create Alert with Targeting**
1. Go to Azure Portal → Monitor → Alerts → + Create → Alert rule
2. **Scope**: Select Log Analytics workspace
3. **Condition**: Custom log search
4. **Paste KQL query** (provided below)
5. **Modify for targeting specific machines:**
   ```kql
   VMProcess
   | where ExecutableName =~ "{process_name}"
   // TARGET FILTERING - Choose one:
   | where Computer has "appserver"  // Hostname pattern
   // OR join with Heartbeat for tag-based filtering:
   | join (Heartbeat | where Tags contains "Role=AppServer") on Computer
   | summarize ProcessCount = dcount(Computer) by bin(TimeGenerated, 5m)
   | where ProcessCount == 0
   ```
6. Set **threshold**: Greater than 0
7. **Evaluation frequency**: Every 5 minutes
8. Create/select **Action Group** for notifications

**Step 4: Test the Alert**
1. Query VMProcess table to verify data flows
2. Stop the process on a test machine
3. Wait 5-10 minutes for alert to trigger

**Why This Is Simple:**
- VM Insights automatically discovers processes
- No configuration needed - just enable it
- Same alert creation process as services
- Built-in process inventory

**Cost Optimization:**
- Consider using Basic logs for VMProcess data if real-time alerting is not required
- Use Auxiliary logs for long-term retention of process inventory data
"""

        return [AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.VM_INSIGHTS,
            description=f"Monitor {process_name} process via VM Insights",
            implementation_notes=implementation_notes,
            complexity=MigrationComplexity.SIMPLE,
            confidence_score=0.9,
            prerequisites=[
                "VM Insights enabled on target machines",
                "Azure Monitor Agent installed",
                "Log Analytics workspace",
            ],
            kql_query=kql_query,
        )]
    
    def _map_log_file_source(
        self,
        data_source: SCOMDataSource,
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map log file monitoring to Azure Monitor."""
        return [AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.DATA_COLLECTION_RULE,
            description="Configure custom log collection via DCR",
            implementation_notes=(
                "Azure Monitor Agent supports custom text log collection. "
                "Configure a Data Collection Rule with custom text log data source "
                "pointing to the log file location.\n\n"
                "**Cost Optimization:**\n"
                "- Use **Basic logs** for high-volume log data that doesn't require real-time alerting\n"
                "- Use **Auxiliary logs** for compliance/archival data with infrequent access\n"
                "- This can reduce ingestion costs by up to 80% compared to Analytics logs"
            ),
            complexity=MigrationComplexity.MODERATE,
            confidence_score=0.8,
            prerequisites=[
                "Azure Monitor Agent installed",
                "Custom log DCR configured with file path pattern",
                "Log Analytics workspace with custom log table",
            ],
            kql_query=f"""// Query custom log table
CustomLog_CL
| where TimeGenerated > ago(1h)
| parse RawData with * // Add parsing logic based on log format
| project TimeGenerated, Computer, ParsedFields
""",
        )]
    
    def _map_http_source(
        self,
        data_source: SCOMDataSource,
        severity: Severity,
        name: str,
    ) -> list[AzureMonitorRecommendation]:
        """Map HTTP/web monitoring to Azure Monitor."""
        return [
            AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.METRIC_ALERT,
                description="Create Application Insights availability test",
                implementation_notes=(
                    "Azure Application Insights provides URL ping tests and multi-step web tests. "
                    "These can monitor endpoint availability from multiple geographic locations."
                ),
                complexity=MigrationComplexity.SIMPLE,
                confidence_score=0.9,
                prerequisites=[
                    "Application Insights resource",
                    "Configure availability test with URL and check frequency",
                ],
            ),
            AzureMonitorRecommendation(
                target_type=AzureMonitorTargetType.LOG_ALERT,
                description="Use Azure Monitor HTTP Data Collector",
                implementation_notes=(
                    "For more complex HTTP monitoring, use Azure Functions to make HTTP requests "
                    "and send results to Log Analytics via the HTTP Data Collector API."
                ),
                complexity=MigrationComplexity.MODERATE,
                confidence_score=0.7,
            ),
        ]
    
    def _generate_perf_kql(self, data_source: SCOMDataSource) -> str:
        """Generate KQL query for performance counter data."""
        obj = data_source.performance_object or "*"
        counter = data_source.performance_counter or "*"
        instance = data_source.performance_instance or "*"
        
        return f"""Perf
| where ObjectName == "{obj}"
| where CounterName == "{counter}"
| where InstanceName == "{instance}"
| summarize AggregatedValue = avg(CounterValue) by bin(TimeGenerated, 5m), Computer
| where AggregatedValue > 90  // Adjust threshold as needed
"""
    
    def _generate_event_kql(self, data_source: SCOMDataSource) -> str:
        """Generate KQL query for Windows event data."""
        log = data_source.event_log or "System"
        
        query = f'Event\n| where EventLog == "{log}"'
        
        if data_source.event_id:
            query += f"\n| where EventID == {data_source.event_id}"
        
        if data_source.event_source:
            query += f'\n| where Source == "{data_source.event_source}"'
        
        query += "\n| project TimeGenerated, Computer, EventID, Source, RenderedDescription"
        
        return query
    
    def _generate_wmi_kql(self, data_source: SCOMDataSource) -> str:
        """Generate KQL query approximation for WMI data."""
        wmi_query = data_source.wmi_query or "SELECT * FROM Win32_ComputerSystem"
        
        return f"""// Original WMI Query: {wmi_query}
// WMI data collected via Azure Monitor Agent custom data source

WMIData_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, Computer, WMIProperties
"""
    
    def _create_generic_recommendation(self, monitor: SCOMMonitor) -> AzureMonitorRecommendation:
        """Create a generic recommendation when no specific mapping exists."""
        return AzureMonitorRecommendation(
            target_type=AzureMonitorTargetType.LOG_ALERT,
            description="Manual migration required",
            implementation_notes=(
                f"This monitor ({monitor.name}) requires manual analysis to determine "
                f"the best Azure Monitor implementation. Review the original monitor "
                f"configuration and create an appropriate Log Analytics query or metric alert."
            ),
            complexity=MigrationComplexity.MANUAL,
            confidence_score=0.3,
            prerequisites=[
                "Review original SCOM monitor configuration",
                "Determine equivalent Azure Monitor data source",
                "Create custom KQL query or metric alert",
            ],
        )
