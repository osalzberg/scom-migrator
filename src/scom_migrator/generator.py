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
        pass
    
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
        
        for mapping in report.mappings:
            if mapping.can_migrate:
                for rec in mapping.recommendations:
                    if rec.target_type in [
                        AzureMonitorTargetType.METRIC_ALERT,
                        AzureMonitorTargetType.LOG_ALERT,
                    ]:
                        resource = self._create_alert_resource(mapping, rec, location)
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
                "allowedValues": ["Analytics", "Basic", "Auxiliary"],
                "metadata": {
                    "description": "Log tier for data collection: Analytics ($3/GB, real-time), Basic ($0.50/GB, 83% cheaper), Auxiliary ($0.05/GB, archival)"
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
        
        for rec in mapping.recommendations:
            resource = self._create_resource_from_recommendation(mapping, rec, location)
            if resource:
                resources.append(resource)
        
        return resources
    
    def _create_resource_from_recommendation(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
    ) -> Optional[ARMResource]:
        """Create an ARM resource from a recommendation."""
        if rec.target_type == AzureMonitorTargetType.METRIC_ALERT:
            return self._create_metric_alert(mapping, rec, location)
        elif rec.target_type == AzureMonitorTargetType.LOG_ALERT:
            return self._create_log_alert(mapping, rec, location)
        elif rec.target_type == AzureMonitorTargetType.DATA_COLLECTION_RULE:
            return None  # DCRs are consolidated separately
        
        return None
    
    def _create_alert_resource(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
    ) -> Optional[ARMResource]:
        """Create an alert resource."""
        if rec.target_type == AzureMonitorTargetType.METRIC_ALERT:
            return self._create_metric_alert(mapping, rec, location)
        elif rec.target_type == AzureMonitorTargetType.LOG_ALERT:
            return self._create_log_alert(mapping, rec, location)
        return None
    
    def _create_metric_alert(
        self,
        mapping: MigrationMapping,
        rec: AzureMonitorRecommendation,
        location: str,
    ) -> ARMResource:
        """Create a metric alert resource."""
        # Sanitize name for Azure resource naming
        safe_name = self._sanitize_resource_name(mapping.source_name)
        
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
    ) -> ARMResource:
        """Create a log alert (scheduled query rule) resource."""
        safe_name = self._sanitize_resource_name(mapping.source_name)
        
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
        log_tier: str = "Basic",  # Default to Basic tier for cost optimization
    ) -> ARMResource:
        """
        Create a Data Collection Rule resource.
        
        Args:
            name: Name of the DCR
            location: Azure region
            perf_counters: List of performance counters to collect
            event_logs: List of event logs to collect
            log_tier: Log tier - "Basic" (default, 83% cheaper), "Analytics", or "Auxiliary"
        """
        data_flows = []
        data_sources = {}
        
        # Performance counters
        if perf_counters:
            perf_specs = []
            for obj, counter, instance in perf_counters:
                perf_specs.append({
                    "objectName": obj,
                    "counterName": counter,
                    "instanceName": instance,
                    "samplingFrequencyInSeconds": 60
                })
            
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
                "destinations": ["logAnalyticsWorkspace"],
                "transformKql": "source | project TimeGenerated, Computer, ObjectName, CounterName, InstanceName, CounterValue"
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
                "destinations": ["logAnalyticsWorkspace"],
                "transformKql": "source | project TimeGenerated, Computer, EventID, EventLevel, EventLevelName, EventData"
            })
        
        properties = {
            "description": f"Data Collection Rule migrated from SCOM (Log tier: {log_tier})",
            "dataSources": data_sources,
            "destinations": {
                "logAnalytics": [
                    {
                        "name": "logAnalyticsWorkspace",
                        "workspaceResourceId": "[parameters('workspaceResourceId')]",
                        "tableMode": log_tier  # "Basic", "Analytics", or "Auxiliary"
                    }
                ]
            },
            "dataFlows": data_flows,
            "streamDeclarations": {
                "Custom-Perf": {
                    "columns": [
                        {"name": "TimeGenerated", "type": "datetime"},
                        {"name": "Computer", "type": "string"},
                        {"name": "ObjectName", "type": "string"},
                        {"name": "CounterName", "type": "string"},
                        {"name": "InstanceName", "type": "string"},
                        {"name": "CounterValue", "type": "real"}
                    ]
                }
            }
        }
        
        return ARMResource(
            type="Microsoft.Insights/dataCollectionRules",
            api_version=self.API_VERSIONS["Microsoft.Insights/dataCollectionRules"],
            name=name,
            location=location,
            properties=properties,
            depends_on=["[variables('workspaceId')]"],
            tags={
                "source": "SCOM Migration",
                "environment": "[parameters('environment')]"
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
        """Sanitize a string for use as an Azure resource name."""
        # Remove invalid characters
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in name)
        # Remove consecutive dashes
        while "--" in safe:
            safe = safe.replace("--", "-")
        # Trim to max length and remove leading/trailing dashes
        safe = safe[:60].strip("-")
        return safe.lower() or "unnamed-resource"
    
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
