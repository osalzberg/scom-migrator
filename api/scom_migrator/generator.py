"""
ARM Template Generator

Generates Azure Resource Manager templates for deploying Azure Monitor
resources based on migration analysis.
"""

import json
from typing import Optional, Any
from datetime import datetime

from .models import (
    MigrationReport,
    MigrationMapping,
    AzureMonitorRecommendation,
    AzureMonitorTargetType,
    MigrationComplexity,
    ARMTemplate,
    ARMResource,
)


class ARMTemplateGenerator:
    """
    Generates ARM templates for Azure Monitor resources.
    
    Creates deployable ARM templates based on migration analysis,
    including alert rules, action groups, and data collection rules.
    """
    
    # API versions for different resource types
    API_VERSIONS = {
        "Microsoft.Insights/metricAlerts": "2018-03-01",
        "Microsoft.Insights/scheduledQueryRules": "2022-06-15",
        "Microsoft.Insights/activityLogAlerts": "2020-10-01",
        "Microsoft.Insights/actionGroups": "2023-01-01",
        "Microsoft.Insights/dataCollectionRules": "2022-06-01",
        "Microsoft.OperationalInsights/workspaces": "2022-10-01",
    }
    
    def __init__(self):
        """Initialize the ARM template generator."""
        self._used_names: set[str] = set()
    
    def generate_from_report(
        self,
        report: MigrationReport,
        resource_group: str = "[resourceGroup().name]",
        location: str = "[resourceGroup().location]",
        workspace_name: str = "scom-migration-workspace",
        include_workspace: bool = True,
        include_action_group: bool = True,
    ) -> dict[str, Any]:
        """
        Generate a complete ARM template from a migration report.
        
        Args:
            report: The migration report to generate from
            resource_group: Target resource group
            location: Azure region
            workspace_name: Name for Log Analytics workspace
            include_workspace: Whether to include workspace creation
            include_action_group: Whether to include action group creation
            
        Returns:
            Dictionary representing the ARM template
        """
        template = ARMTemplate(
            parameters=self._generate_parameters(workspace_name),
            variables=self._generate_variables(report),
        )
        
        # Reset used names for this template
        self._used_names = set()
        
        # Add Log Analytics workspace if requested
        if include_workspace:
            template.resources.append(self._create_workspace_resource(location))
        
        # Add action group if requested
        if include_action_group:
            template.resources.append(self._create_action_group_resource(location))
        
        # Generate resources from mappings
        for mapping in report.mappings:
            if mapping.can_migrate and mapping.migration_complexity != MigrationComplexity.MANUAL:
                resources = self._generate_resources_from_mapping(mapping, location)
                template.resources.extend(resources)
        
        # Add outputs
        template.outputs = self._generate_outputs(template.resources)
        
        return template.to_dict()
    
    def generate_alert_rules_only(
        self,
        report: MigrationReport,
        location: str = "[resourceGroup().location]",
    ) -> dict[str, Any]:
        """
        Generate ARM template with only alert rules.
        
        Args:
            report: The migration report
            location: Azure region
            
        Returns:
            ARM template dictionary
        """
        template = ARMTemplate(
            parameters={
                "workspaceResourceId": {
                    "type": "string",
                    "metadata": {
                        "description": "Resource ID of the Log Analytics workspace"
                    }
                },
                "actionGroupResourceId": {
                    "type": "string",
                    "metadata": {
                        "description": "Resource ID of the Action Group for alerts"
                    }
                },
            },
        )
        
        # Reset used names for this template
        self._used_names = set()
        
        for mapping in report.mappings:
            if mapping.can_migrate:
                for index, rec in enumerate(mapping.recommendations):
                    if rec.target_type in [
                        AzureMonitorTargetType.METRIC_ALERT,
                        AzureMonitorTargetType.LOG_ALERT,
                    ]:
                        resource = self._create_alert_resource(mapping, rec, location, index)
                        if resource:
                            template.resources.append(resource)
        
        return template.to_dict()
    
    def generate_data_collection_rules(
        self,
        report: MigrationReport,
        location: str = "[resourceGroup().location]",
    ) -> dict[str, Any]:
        """
        Generate ARM template for Data Collection Rules.
        
        Args:
            report: The migration report
            location: Azure region
            
        Returns:
            ARM template dictionary
        """
        template = ARMTemplate(
            parameters={
                "workspaceResourceId": {
                    "type": "string",
                    "metadata": {
                        "description": "Resource ID of the Log Analytics workspace"
                    }
                },
                "dataCollectionEndpointId": {
                    "type": "string",
                    "defaultValue": "",
                    "metadata": {
                        "description": "Resource ID of Data Collection Endpoint (optional)"
                    }
                },
            },
            variables={
                "workspaceId": "[parameters('workspaceResourceId')]"
            },
        )
        
        # Collect unique data sources from recommendations
        perf_counters = set()
        event_logs = set()
        
        for mapping in report.mappings:
            for rec in mapping.recommendations:
                if rec.target_type == AzureMonitorTargetType.DATA_COLLECTION_RULE:
                    # Extract data source details from notes
                    notes = rec.implementation_notes.lower()
                    if "performance" in notes:
                        perf_counters.add(("Processor", "% Processor Time", "*"))
                        perf_counters.add(("Memory", "Available MBytes", "*"))
                        perf_counters.add(("LogicalDisk", "% Free Space", "*"))
                    if "event" in notes:
                        event_logs.add("System")
                        event_logs.add("Application")
        
        # Create consolidated DCR
        dcr = self._create_data_collection_rule(
            name="scom-migration-dcr",
            location=location,
            perf_counters=list(perf_counters),
            event_logs=list(event_logs),
        )
        template.resources.append(dcr)
        
        return template.to_dict()
    
    def _generate_parameters(self, workspace_name: str) -> dict[str, Any]:
        """Generate ARM template parameters."""
        return {
            "workspaceName": {
                "type": "string",
                "defaultValue": workspace_name,
                "metadata": {
                    "description": "Name of the Log Analytics workspace"
                }
            },
            "actionGroupName": {
                "type": "string",
                "defaultValue": "scom-migration-ag",
                "metadata": {
                    "description": "Name of the Action Group for alerts"
                }
            },
            "actionGroupEmail": {
                "type": "string",
                "defaultValue": "",
                "metadata": {
                    "description": "Email address for alert notifications"
                }
            },
            "environment": {
                "type": "string",
                "defaultValue": "production",
                "allowedValues": ["production", "staging", "development"],
                "metadata": {
                    "description": "Environment tag for resources"
                }
            },
            "logTier": {
                "type": "string",
                "defaultValue": "Basic",
                "allowedValues": ["Analytics", "Basic"],
                "metadata": {
                    "description": "Log tier for data collection: Analytics ($3/GB, real-time alerts), Basic ($0.50/GB, 83% cheaper, delayed alerts). Note: Auxiliary tier ($0.05/GB) cannot be used for alerting."
                }
            },
            "targetVmResourceIds": {
                "type": "array",
                "defaultValue": [],
                "metadata": {
                    "description": "Array of VM resource IDs to monitor. Example: ['/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}']"
                }
            },
        }
    
    def _generate_variables(self, report: MigrationReport) -> dict[str, Any]:
        """Generate ARM template variables."""
        return {
            "workspaceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]",
            "actionGroupId": "[resourceId('Microsoft.Insights/actionGroups', parameters('actionGroupName'))]",
            "migrationSource": report.management_pack.name,
            "migrationDate": datetime.now().strftime("%Y-%m-%d"),
        }
    
    def _create_workspace_resource(self, location: str) -> ARMResource:
        """Create Log Analytics workspace resource."""
        return ARMResource(
            type="Microsoft.OperationalInsights/workspaces",
            api_version=self.API_VERSIONS["Microsoft.OperationalInsights/workspaces"],
            name="[parameters('workspaceName')]",
            location=location,
            properties={
                "sku": {
                    "name": "PerGB2018"
                },
                "retentionInDays": 30,
                "features": {
                    "enableLogAccessUsingOnlyResourcePermissions": True
                }
            },
            tags={
                "source": "SCOM Migration",
                "environment": "[parameters('environment')]"
            }
        )
    
    def _create_action_group_resource(self, location: str) -> ARMResource:
        """Create Action Group resource with multiple notification options."""
        return ARMResource(
            type="Microsoft.Insights/actionGroups",
            api_version=self.API_VERSIONS["Microsoft.Insights/actionGroups"],
            name="[parameters('actionGroupName')]",
            location="global",
            properties={
                "groupShortName": "SCOMMigrate",
                "enabled": True,
                "emailReceivers": [
                    {
                        "name": "EmailAction",
                        "emailAddress": "[if(empty(parameters('actionGroupEmail')), 'alerts@example.com', parameters('actionGroupEmail'))]",
                        "useCommonAlertSchema": True
                    }
                ],
                "smsReceivers": [],
                "webhookReceivers": [],
                "armRoleReceivers": [
                    {
                        "name": "MonitoringContributor",
                        "roleId": "749f88d5-cbae-40b8-bcfc-e573ddc772fa",
                        "useCommonAlertSchema": True
                    }
                ],
                "azureAppPushReceivers": [],
                "itsmReceivers": [],
                "automationRunbookReceivers": [],
                "voiceReceivers": [],
                "logicAppReceivers": [],
                "azureFunctionReceivers": [],
                "eventHubReceivers": []
            },
            tags={
                "source": "SCOM Migration",
                "environment": "[parameters('environment')]",
                "description": "Migrated from SCOM notification subscribers"
            }
        )
    
    def _generate_resources_from_mapping(
        self,
        mapping: MigrationMapping,
        location: str,
    ) -> list[ARMResource]:
        """Generate ARM resources from a mapping."""
        resources = []
        
        for index, rec in enumerate(mapping.recommendations):
            resource = self._create_resource_from_recommendation(mapping, rec, location, index)
            if resource:
                resources.append(resource)
        
        return resources
    
    def _create_resource_from_recommendation(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
        index: int = 0,
    ) -> Optional[ARMResource]:
        """Create an ARM resource from a recommendation."""
        if rec.target_type == AzureMonitorTargetType.METRIC_ALERT:
            return self._create_metric_alert(mapping, rec, location, index)
        elif rec.target_type == AzureMonitorTargetType.LOG_ALERT:
            return self._create_log_alert(mapping, rec, location, index)
        elif rec.target_type == AzureMonitorTargetType.DATA_COLLECTION_RULE:
            return None  # DCRs are consolidated separately
        
        return None
    
    def _create_alert_resource(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
        index: int = 0,
    ) -> Optional[ARMResource]:
        """Create an alert resource."""
        if rec.target_type == AzureMonitorTargetType.METRIC_ALERT:
            return self._create_metric_alert(mapping, rec, location, index)
        elif rec.target_type == AzureMonitorTargetType.LOG_ALERT:
            return self._create_log_alert(mapping, rec, location, index)
        return None
    
    def _create_metric_alert(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
        index: int = 0,
    ) -> ARMResource:
        """Create a metric alert resource."""
        # Sanitize name for Azure resource naming and make it unique
        safe_name = self._sanitize_resource_name(f"{mapping.source_name}-{index}")
        
        # Use ARM snippet if provided, otherwise create default
        properties = rec.arm_template_snippet.get("properties", {}) if rec.arm_template_snippet else {}
        
        default_properties = {
            "description": f"Migrated from SCOM: {mapping.source_name}",
            "severity": properties.get("severity", 2),
            "enabled": True,
            "scopes": ["[parameters('targetResourceId')]"],
            "evaluationFrequency": "PT5M",
            "windowSize": "PT5M",
            "criteria": properties.get("criteria", {
                "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                "allOf": []
            }),
            "actions": [
                {
                    "actionGroupId": "[variables('actionGroupId')]"
                }
            ]
        }
        
        return ARMResource(
            type="Microsoft.Insights/metricAlerts",
            api_version=self.API_VERSIONS["Microsoft.Insights/metricAlerts"],
            name=f"alert-{safe_name}",
            location="global",
            properties=default_properties,
            depends_on=["[variables('actionGroupId')]"],
            tags={
                "source": "SCOM Migration",
                "originalId": mapping.source_id,
                "environment": "[parameters('environment')]"
            }
        )
    
    def _create_log_alert(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
        index: int = 0,
    ) -> ARMResource:
        """Create a log alert (scheduled query rule) resource."""
        safe_name = self._sanitize_resource_name(f"{mapping.source_name}-{index}")
        
        # Get KQL query from recommendation
        query = rec.kql_query or "// TODO: Add KQL query"
        
        properties = {
            "description": f"Migrated from SCOM: {mapping.source_name}",
            "severity": 2,
            "enabled": True,
            "scopes": ["[variables('workspaceId')]"],
            "evaluationFrequency": "PT5M",
            "windowSize": "PT5M",
            "criteria": {
                "allOf": [
                    {
                        "query": query,
                        "timeAggregation": "Count",
                        "operator": "GreaterThan",
                        "threshold": 0,
                        "failingPeriods": {
                            "numberOfEvaluationPeriods": 1,
                            "minFailingPeriodsToAlert": 1
                        }
                    }
                ]
            },
            "actions": {
                "actionGroups": ["[variables('actionGroupId')]"]
            }
        }
        
        return ARMResource(
            type="Microsoft.Insights/scheduledQueryRules",
            api_version=self.API_VERSIONS["Microsoft.Insights/scheduledQueryRules"],
            name=f"alert-{safe_name}",
            location=location,
            properties=properties,
            depends_on=[
                "[variables('workspaceId')]",
                "[variables('actionGroupId')]"
            ],
            tags={
                "source": "SCOM Migration",
                "originalId": mapping.source_id,
                "environment": "[parameters('environment')]"
            }
        )
    
    def _create_data_collection_rule(
        self,
        name: str,
        location: str,
        perf_counters: list[tuple[str, str, str]],
        event_logs: list[str],
        log_tier: str = "[parameters('logTier')]",  # Use parameter for log tier
    ) -> ARMResource:
        """
        Create a Data Collection Rule resource.
        
        Args:
            name: Name of the DCR
            location: Azure region
            perf_counters: List of performance counters to collect
            event_logs: List of event logs to collect
            log_tier: Log tier - defaults to template parameter
        """
        data_flows = []
        data_sources = {}
        
        # Performance counters
        if perf_counters:
            data_sources["performanceCounters"] = [
                {
                    "name": "perfCounterDataSource",
                    "streams": ["Microsoft-Perf"],
                    "samplingFrequencyInSeconds": 60,
                    "counterSpecifiers": [
                        f"\\{obj}({inst})\\{counter}" 
                        for obj, counter, inst in perf_counters
                    ]
                }
            ]
            data_flows.append({
                "streams": ["Microsoft-Perf"],
                "destinations": ["logAnalyticsWorkspace"]
            })
        
        # Windows events
        if event_logs:
            data_sources["windowsEventLogs"] = [
                {
                    "name": "eventLogsDataSource",
                    "streams": ["Microsoft-Event"],
                    "xPathQueries": [
                        f"{log}!*[System[(Level=1 or Level=2 or Level=3)]]"
                        for log in event_logs
                    ]
                }
            ]
            data_flows.append({
                "streams": ["Microsoft-Event"],
                "destinations": ["logAnalyticsWorkspace"]
            })
        
        properties = {
            "description": f"Data Collection Rule migrated from SCOM - Log tier controlled by template parameter",
            "kind": "Windows",  # CRITICAL: Must specify Windows or Linux
            "dataSources": data_sources,
            "destinations": {
                "logAnalytics": [
                    {
                        "name": "logAnalyticsWorkspace",
                        "workspaceResourceId": "[parameters('workspaceResourceId')]"
                    }
                ]
            },
            "dataFlows": data_flows
        }
        
        return ARMResource(
            type="Microsoft.Insights/dataCollectionRules",
            api_version=self.API_VERSIONS["Microsoft.Insights/dataCollectionRules"],
            name=name,
            location=location,
            kind="Windows",  # CRITICAL: Must be set at resource level too
            properties=properties,
            tags={
                "source": "SCOM Migration",
                "logTier": log_tier,
            }
        )
    
    def _generate_outputs(self, resources: list[ARMResource]) -> dict[str, Any]:
        """Generate ARM template outputs."""
        outputs = {}
        
        # Check for workspace
        workspace_resources = [r for r in resources if "workspaces" in r.type]
        if workspace_resources:
            outputs["workspaceId"] = {
                "type": "string",
                "value": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
            }
        
        # Check for action group
        ag_resources = [r for r in resources if "actionGroups" in r.type]
        if ag_resources:
            outputs["actionGroupId"] = {
                "type": "string",
                "value": "[resourceId('Microsoft.Insights/actionGroups', parameters('actionGroupName'))]"
            }
        
        # Count alert rules
        alert_count = len([r for r in resources if "Alert" in r.type or "scheduledQueryRules" in r.type])
        outputs["alertRulesCreated"] = {
            "type": "int",
            "value": alert_count
        }
        
        return outputs
    
    def _sanitize_resource_name(self, name: str) -> str:
        """Sanitize a string for use as an Azure resource name and ensure uniqueness."""
        # Remove invalid characters
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in name)
        # Remove consecutive dashes
        while "--" in safe:
            safe = safe.replace("--", "-")
        # Trim to max length and remove leading/trailing dashes
        safe = safe[:55].strip("-").lower() or "unnamed-resource"
        
        # Ensure uniqueness by adding a suffix if needed
        original_safe = safe
        counter = 1
        while safe in self._used_names:
            safe = f"{original_safe[:50]}-{counter}"
            counter += 1
        
        self._used_names.add(safe)
        return safe
    
    def export_template(
        self,
        template: dict[str, Any],
        output_path: str,
        indent: int = 2,
    ) -> None:
        """
        Export an ARM template to a file.
        
        Args:
            template: The ARM template dictionary
            output_path: Path to write the template
            indent: JSON indentation level
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=indent)
    
    def validate_template(self, template: dict[str, Any]) -> tuple[bool, list[str]]:
        """
        Validate ARM template for common issues.
        
        Args:
            template: The ARM template dictionary
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required fields
        if "$schema" not in template:
            errors.append("Missing required field: $schema")
        if "contentVersion" not in template:
            errors.append("Missing required field: contentVersion")
        if "resources" not in template:
            errors.append("Missing required field: resources")
        
        # Check resources
        if "resources" in template:
            for i, resource in enumerate(template["resources"]):
                resource_name = resource.get("name", f"resource_{i}")
                
                if "type" not in resource:
                    errors.append(f"Resource '{resource_name}': Missing 'type' field")
                if "apiVersion" not in resource:
                    errors.append(f"Resource '{resource_name}': Missing 'apiVersion' field")
                if "name" not in resource:
                    errors.append(f"Resource index {i}: Missing 'name' field")
                
                # Check DCR specific requirements
                if "dataCollectionRules" in resource.get("type", ""):
                    props = resource.get("properties", {})
                    if "destinations" not in props:
                        errors.append(f"DCR '{resource_name}': Missing 'destinations' configuration")
                    if "dataFlows" not in props:
                        errors.append(f"DCR '{resource_name}': Missing 'dataFlows' configuration")
                    if not props.get("dataSources"):
                        errors.append(f"DCR '{resource_name}': Missing 'dataSources' configuration")
        
        return (len(errors) == 0, errors)
    
    def export_bicep(
        self,
        template: dict[str, Any],
        output_path: str,
    ) -> str:
        """
        Generate Bicep template from ARM template.
        
        Note: This is a simplified conversion. For complex templates,
        use the official ARM to Bicep conversion tools.
        
        Args:
            template: The ARM template dictionary
            output_path: Path to write the Bicep file
            
        Returns:
            Bicep template content
        """
        bicep_lines = [
            "// Bicep template generated from SCOM migration",
            "// Note: Review and adjust as needed",
            "",
        ]
        
        # Parameters
        for param_name, param_def in template.get("parameters", {}).items():
            param_type = param_def.get("type", "string")
            default = param_def.get("defaultValue")
            
            if default is not None:
                if isinstance(default, str):
                    bicep_lines.append(f"param {param_name} {param_type} = '{default}'")
                else:
                    bicep_lines.append(f"param {param_name} {param_type} = {json.dumps(default)}")
            else:
                bicep_lines.append(f"param {param_name} {param_type}")
        
        bicep_lines.append("")
        
        # Variables
        for var_name, var_value in template.get("variables", {}).items():
            if isinstance(var_value, str):
                # Simple conversion of ARM expressions
                bicep_value = var_value.replace("[", "").replace("]", "")
                bicep_lines.append(f"var {var_name} = {bicep_value}")
            else:
                bicep_lines.append(f"var {var_name} = {json.dumps(var_value)}")
        
        bicep_lines.append("")
        
        # Resources (simplified)
        for resource in template.get("resources", []):
            res_type = resource.get("type", "")
            api_version = resource.get("apiVersion", "")
            res_name = resource.get("name", "unnamed")
            
            # Create symbolic name
            symbolic = res_name.replace("[", "").replace("]", "").replace("parameters('", "").replace("')", "")
            symbolic = "".join(c if c.isalnum() else "_" for c in symbolic)
            
            bicep_lines.append(f"resource {symbolic} '{res_type}@{api_version}' = {{")
            bicep_lines.append(f"  name: '{res_name}'")
            bicep_lines.append(f"  location: '{resource.get('location', 'global')}'")
            bicep_lines.append(f"  properties: {json.dumps(resource.get('properties', {}), indent=4)}")
            bicep_lines.append("}")
            bicep_lines.append("")
        
        bicep_content = "\n".join(bicep_lines)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(bicep_content)
        
        return bicep_content

    def generate_workbook(
        self,
        report: MigrationReport,
        workbook_name: str = "SCOM Migration Dashboard",
    ) -> dict[str, Any]:
        """
        Generate an Azure Workbook template for monitoring dashboard.
        
        Args:
            report: The migration report
            workbook_name: Name for the workbook
            
        Returns:
            Workbook ARM template dictionary
        """
        mp_name = report.management_pack.display_name or report.management_pack.name
        
        # Build workbook items
        items = []
        
        # Header section
        items.append({
            "type": 1,
            "content": {
                "json": f"# {mp_name} - Monitoring Dashboard\n\nThis workbook provides monitoring views migrated from SCOM Management Pack."
            },
            "name": "header"
        })
        
        # Migration summary section
        total = report.total_components
        migratable = report.migratable_components
        items.append({
            "type": 1,
            "content": {
                "json": f"## Migration Summary\n- **Total Components**: {total}\n- **Migratable**: {migratable}\n- **Migration Rate**: {(migratable/total*100) if total > 0 else 0:.0f}%"
            },
            "name": "summary"
        })
        
        # Performance counters section if applicable
        perf_queries = []
        event_queries = []
        service_queries = []
        
        for mapping in report.mappings:
            for rec in mapping.recommendations:
                if rec.kql_query:
                    query = rec.kql_query
                    if "Perf" in query:
                        perf_queries.append((mapping.source_name, query))
                    elif "Event" in query:
                        event_queries.append((mapping.source_name, query))
        
        # Add performance monitoring section
        if perf_queries:
            items.append({
                "type": 1,
                "content": {"json": "## Performance Monitoring"}
            })
            items.append({
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "Perf\n| where TimeGenerated > ago(1h)\n| summarize avg(CounterValue) by CounterName, bin(TimeGenerated, 5m)\n| render timechart",
                    "size": 0,
                    "title": "Performance Counters Overview",
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "timechart"
                },
                "name": "perfChart"
            })
        
        # Add event monitoring section
        if event_queries:
            items.append({
                "type": 1,
                "content": {"json": "## Event Monitoring"}
            })
            items.append({
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "Event\n| where TimeGenerated > ago(24h)\n| where EventLevelName in ('Error', 'Warning')\n| summarize count() by EventLog, EventLevelName, bin(TimeGenerated, 1h)\n| render columnchart",
                    "size": 0,
                    "title": "Events by Log and Severity",
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "categoricalbar"
                },
                "name": "eventChart"
            })
            items.append({
                "type": 3,
                "content": {
                    "version": "KqlItem/1.0",
                    "query": "Event\n| where TimeGenerated > ago(24h)\n| where EventLevelName in ('Error', 'Warning')\n| project TimeGenerated, Computer, EventLog, EventID, EventLevelName, RenderedDescription\n| order by TimeGenerated desc\n| take 100",
                    "size": 0,
                    "title": "Recent Error and Warning Events",
                    "queryType": 0,
                    "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": "table"
                },
                "name": "eventTable"
            })
        
        # Service health section
        items.append({
            "type": 1,
            "content": {"json": "## Service Health"}
        })
        items.append({
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "Event\n| where TimeGenerated > ago(24h)\n| where EventLog == 'System' and EventID == 7036\n| parse RenderedDescription with ServiceName \" service \" ServiceState \" \" *\n| where ServiceState has 'stopped'\n| summarize StopCount=count() by ServiceName\n| order by StopCount desc\n| take 20",
                "size": 0,
                "title": "Services with Stop Events (Last 24h)",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "table"
            },
            "name": "serviceHealth"
        })
        
        # Alerts section
        items.append({
            "type": 1,
            "content": {"json": "## Active Alerts"}
        })
        items.append({
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AlertsManagementResources\n| where type == 'microsoft.alertsmanagement/alerts'\n| where properties.essentials.alertState == 'New'\n| project AlertName=properties.essentials.alertRule, Severity=properties.essentials.severity, StartTime=properties.essentials.startDateTime\n| order by StartTime desc",
                "size": 0,
                "title": "Active Alerts",
                "queryType": 1,
                "resourceType": "microsoft.resourcegraph/resources",
                "visualization": "table"
            },
            "name": "activeAlerts"
        })
        
        # Build workbook content
        workbook_content = {
            "version": "Notebook/1.0",
            "items": items,
            "fallbackResourceIds": ["/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}"],
            "styleSettings": {},
            "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
        }
        
        # Build ARM template
        template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "workbookDisplayName": {
                    "type": "string",
                    "defaultValue": workbook_name,
                    "metadata": {"description": "Display name for the workbook"}
                },
                "workspaceName": {
                    "type": "string",
                    "defaultValue": "",
                    "metadata": {"description": "Name of existing Log Analytics workspace (if in same resource group). Leave empty if using workspaceResourceId."}
                },
                "workspaceResourceId": {
                    "type": "string",
                    "defaultValue": "",
                    "metadata": {"description": "Full Resource ID of workspace. Leave empty if workspace is in same resource group and you provided workspaceName. Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}"}
                }
            },
            "variables": {
                "actualWorkspaceResourceId": "[if(empty(parameters('workspaceResourceId')), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), parameters('workspaceResourceId'))]"
            },
            "resources": [
                {
                    "type": "Microsoft.Insights/workbooks",
                    "apiVersion": "2022-04-01",
                    "name": "[guid(parameters('workbookDisplayName'))]",
                    "location": "[resourceGroup().location]",
                    "kind": "shared",
                    "properties": {
                        "displayName": "[parameters('workbookDisplayName')]",
                        "serializedData": json.dumps(workbook_content),
                        "sourceId": "[variables('actualWorkspaceResourceId')]",
                        "category": "workbook"
                    },
                    "tags": {
                        "source": "SCOM Migration",
                        "migratedFrom": mp_name
                    }
                }
            ],
            "outputs": {
                "workbookId": {
                    "type": "string",
                    "value": "[resourceId('Microsoft.Insights/workbooks', guid(parameters('workbookDisplayName')))]"
                }
            }
        }
        
        return template

    def generate_custom_log_dcr(
        self,
        report: MigrationReport,
        location: str = "[resourceGroup().location]",
    ) -> dict[str, Any]:
        """
        Generate DCR for custom log collection from script outputs.
        
        Args:
            report: The migration report
            location: Azure region
            
        Returns:
            ARM template for custom log DCR
        """
        mp_name = report.management_pack.name.replace(".", "-").lower()
        
        template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "workspaceResourceId": {
                    "type": "string",
                    "metadata": {"description": "Resource ID of the Log Analytics workspace"}
                },
                "dataCollectionEndpointId": {
                    "type": "string",
                    "defaultValue": "",
                    "metadata": {"description": "Resource ID of Data Collection Endpoint (required for custom logs)"}
                },
                "customLogPath": {
                    "type": "string",
                    "defaultValue": "C:\\\\Logs\\\\SCOMScripts\\\\*.log",
                    "metadata": {"description": "Path pattern for custom log files generated by migrated scripts"}
                }
            },
            "variables": {
                "customTableName": f"Custom_{mp_name}_CL"
            },
            "resources": [
                {
                    "type": "Microsoft.Insights/dataCollectionRules",
                    "apiVersion": "2022-06-01",
                    "name": f"dcr-customlog-{mp_name}",
                    "location": location,
                    "kind": "Windows",
                    "properties": {
                        "description": f"Custom log collection for scripts migrated from SCOM MP: {report.management_pack.display_name or report.management_pack.name}",
                        "dataCollectionEndpointId": "[if(empty(parameters('dataCollectionEndpointId')), null(), parameters('dataCollectionEndpointId'))]",
                        "streamDeclarations": {
                            "Custom-TextLog": {
                                "columns": [
                                    {"name": "TimeGenerated", "type": "datetime"},
                                    {"name": "RawData", "type": "string"},
                                    {"name": "Computer", "type": "string"},
                                    {"name": "FilePath", "type": "string"}
                                ]
                            }
                        },
                        "dataSources": {
                            "logFiles": [
                                {
                                    "name": "customLogDataSource",
                                    "streams": ["Custom-TextLog"],
                                    "filePatterns": ["[parameters('customLogPath')]"],
                                    "format": "text",
                                    "settings": {
                                        "text": {
                                            "recordStartTimestampFormat": "ISO 8601"
                                        }
                                    }
                                }
                            ]
                        },
                        "destinations": {
                            "logAnalytics": [
                                {
                                    "name": "logAnalyticsWorkspace",
                                    "workspaceResourceId": "[parameters('workspaceResourceId')]"
                                }
                            ]
                        },
                        "dataFlows": [
                            {
                                "streams": ["Custom-TextLog"],
                                "destinations": ["logAnalyticsWorkspace"],
                                "transformKql": "source | extend TimeGenerated = now()",
                                "outputStream": "[variables('customTableName')]"
                            }
                        ]
                    },
                    "tags": {
                        "source": "SCOM Migration",
                        "purpose": "Custom log collection for migrated scripts"
                    }
                }
            ],
            "outputs": {
                "dcrId": {
                    "type": "string",
                    "value": f"[resourceId('Microsoft.Insights/dataCollectionRules', 'dcr-customlog-{mp_name}')]"
                },
                "customTableName": {
                    "type": "string", 
                    "value": "[variables('customTableName')]"
                }
            }
        }
        
        return template

    def generate_complete_deployment(
        self,
        report: MigrationReport,
        location: str = "[resourceGroup().location]",
    ) -> dict[str, Any]:
        """
        Generate a single combined ARM template with all resources.
        
        Combines alert rules, DCRs, workbook, and custom log DCR into one template.
        Optionally creates a new Log Analytics workspace.
        
        Args:
            report: The migration report
            location: Azure region
            
        Returns:
            Combined ARM template dictionary
        """
        mp_name = report.management_pack.name.replace(".", "-").lower()
        mp_display = report.management_pack.display_name or report.management_pack.name
        
        # Get individual templates
        arm_template = self.generate_from_report(report)
        dcr_template = self.generate_data_collection_rules(report)
        workbook_template = self.generate_workbook(report)
        custom_log_dcr = self.generate_custom_log_dcr(report)
        
        # Combine parameters (deduplicate)
        combined_params = {
            "createNewWorkspace": {
                "type": "bool",
                "defaultValue": False,
                "metadata": {"description": "Set to true to create a new Log Analytics workspace, false to use existing"}
            },
            "workspaceName": {
                "type": "string",
                "defaultValue": f"law-scom-migration-{mp_name[:20]}",
                "metadata": {"description": "Name of the Log Analytics workspace (new or existing)"}
            },
            "workspaceResourceId": {
                "type": "string",
                "defaultValue": "",
                "metadata": {"description": "Full resource ID of existing workspace (leave empty if creating new)"}
            },
            "workspaceSku": {
                "type": "string",
                "defaultValue": "PerGB2018",
                "allowedValues": ["PerGB2018", "Free", "Standalone", "PerNode", "Standard", "Premium"],
                "metadata": {"description": "SKU for new workspace (only used if createNewWorkspace is true)"}
            },
            "workspaceRetentionDays": {
                "type": "int",
                "defaultValue": 30,
                "minValue": 7,
                "maxValue": 730,
                "metadata": {"description": "Data retention in days for new workspace"}
            },
            "actionGroupName": {
                "type": "string",
                "defaultValue": "scom-migration-ag",
                "metadata": {"description": "Name of the action group for alert notifications"}
            },
            "actionGroupEmail": {
                "type": "string",
                "defaultValue": "alerts@company.com",
                "metadata": {"description": "Email address for alert notifications"}
            },
            "environment": {
                "type": "string",
                "defaultValue": "Production",
                "allowedValues": ["Production", "Staging", "Development", "Test"],
                "metadata": {"description": "Environment tag for resources"}
            },
            "workbookDisplayName": {
                "type": "string",
                "defaultValue": f"{mp_display} - Monitoring Dashboard",
                "metadata": {"description": "Display name for the workbook"}
            },
            "dataCollectionEndpointId": {
                "type": "string",
                "defaultValue": "",
                "metadata": {"description": "Resource ID of Data Collection Endpoint (optional, for custom logs)"}
            },
            "customLogPath": {
                "type": "string",
                "defaultValue": "C:\\\\Logs\\\\SCOMScripts\\\\*.log",
                "metadata": {"description": "Path pattern for custom log files from migrated scripts"}
            }
        }
        
        # Combine variables - use conditional for workspace resource ID
        combined_vars = {
            "actualWorkspaceResourceId": "[if(parameters('createNewWorkspace'), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), parameters('workspaceResourceId'))]",
            "actionGroupId": "[resourceId('Microsoft.Insights/actionGroups', parameters('actionGroupName'))]",
            "customTableName": f"Custom_{mp_name}_CL"
        }
        
        # Combine all resources
        combined_resources = []
        
        # Add Log Analytics workspace (conditional)
        workspace_resource = {
            "condition": "[parameters('createNewWorkspace')]",
            "type": "Microsoft.OperationalInsights/workspaces",
            "apiVersion": "2022-10-01",
            "name": "[parameters('workspaceName')]",
            "location": "[resourceGroup().location]",
            "properties": {
                "sku": {
                    "name": "[parameters('workspaceSku')]"
                },
                "retentionInDays": "[parameters('workspaceRetentionDays')]",
                "features": {
                    "enableLogAccessUsingOnlyResourcePermissions": True
                }
            },
            "tags": {
                "source": "SCOM Migration",
                "migratedFrom": mp_display
            }
        }
        combined_resources.append(workspace_resource)
        
        # Add action group from ARM template
        for res in arm_template.get("resources", []):
            if res.get("type") == "Microsoft.Insights/actionGroups":
                combined_resources.append(res)
                break
        
        # Add alert rules from ARM template (with dependency on workspace if creating new)
        for res in arm_template.get("resources", []):
            if res.get("type") == "Microsoft.Insights/scheduledQueryRules":
                alert_res = res.copy()
                # Add conditional dependency on workspace
                alert_res["dependsOn"] = alert_res.get("dependsOn", []) + [
                    "[if(parameters('createNewWorkspace'), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), '')]"
                ]
                combined_resources.append(alert_res)
        
        # Add DCRs (with dependency on workspace if creating new)
        for res in dcr_template.get("resources", []):
            dcr_res = res.copy()
            dcr_res["dependsOn"] = [
                "[if(parameters('createNewWorkspace'), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), '')]"
            ]
            # Update workspaceResourceId reference
            if "properties" in dcr_res and "destinations" in dcr_res.get("properties", {}):
                props = dcr_res["properties"].copy()
                if "logAnalytics" in props.get("destinations", {}):
                    for la in props["destinations"]["logAnalytics"]:
                        la["workspaceResourceId"] = "[variables('actualWorkspaceResourceId')]"
                dcr_res["properties"] = props
            combined_resources.append(dcr_res)
        
        # Add workbook (modify to use variable)
        for res in workbook_template.get("resources", []):
            if res.get("type") == "Microsoft.Insights/workbooks":
                workbook_res = res.copy()
                workbook_res["properties"] = res["properties"].copy()
                workbook_res["properties"]["displayName"] = "[parameters('workbookDisplayName')]"
                workbook_res["properties"]["sourceId"] = "[variables('actualWorkspaceResourceId')]"
                workbook_res["dependsOn"] = [
                    "[if(parameters('createNewWorkspace'), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), '')]"
                ]
                combined_resources.append(workbook_res)
        
        # Add custom log DCR (with dependency)
        for res in custom_log_dcr.get("resources", []):
            custom_res = res.copy()
            custom_res["dependsOn"] = [
                "[if(parameters('createNewWorkspace'), resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), '')]"
            ]
            # Update workspaceResourceId reference
            if "properties" in custom_res and "destinations" in custom_res.get("properties", {}):
                props = custom_res["properties"].copy()
                if "logAnalytics" in props.get("destinations", {}):
                    for la in props["destinations"]["logAnalytics"]:
                        la["workspaceResourceId"] = "[variables('actualWorkspaceResourceId')]"
                custom_res["properties"] = props
            combined_resources.append(custom_res)
        
        # Build combined template
        combined_template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "metadata": {
                "description": f"Complete SCOM to Azure Monitor migration deployment for {mp_display}",
                "author": "SCOM Migration Tool",
                "generatedAt": datetime.utcnow().isoformat()
            },
            "parameters": combined_params,
            "variables": combined_vars,
            "resources": combined_resources,
            "outputs": {
                "workspaceResourceId": {
                    "type": "string",
                    "value": "[variables('actualWorkspaceResourceId')]"
                },
                "actionGroupId": {
                    "type": "string",
                    "value": "[resourceId('Microsoft.Insights/actionGroups', 'scom-migration-ag')]"
                },
                "alertRulesDeployed": {
                    "type": "int",
                    "value": len([r for r in combined_resources if r.get("type") == "Microsoft.Insights/scheduledQueryRules"])
                },
                "dcrDeployed": {
                    "type": "int",
                    "value": len([r for r in combined_resources if r.get("type") == "Microsoft.Insights/dataCollectionRules"])
                },
                "workbookId": {
                    "type": "string",
                    "value": "[resourceId('Microsoft.Insights/workbooks', guid(parameters('workbookDisplayName')))]"
                }
            }
        }
        
        return combined_template

