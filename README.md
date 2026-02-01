# SCOM to Azure Monitor Migration Tool

A comprehensive tool for migrating System Center Operations Manager (SCOM) Management Packs to Azure Monitor. This tool analyzes your existing SCOM monitoring configurations and generates recommendations, KQL queries, and ARM templates for implementing equivalent monitoring in Azure.

## Features

- **Management Pack Parsing**: Parse SCOM Management Pack XML files to extract monitors, rules, discoveries, and class definitions
- **Intelligent Mapping**: Map SCOM monitoring concepts to Azure Monitor equivalents
- **Migration Analysis**: Generate detailed reports with migration complexity assessment
- **ARM Template Generation**: Automatically generate Azure Resource Manager templates for deployment
- **KQL Query Generation**: Create Log Analytics queries equivalent to SCOM monitoring logic
- **CLI Interface**: Easy-to-use command-line interface with rich output

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Install from source

```bash
# Clone the repository
git clone https://github.com/yourusername/scom-migrator.git
cd scom-migrator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### Analyze a Management Pack

```bash
# Basic analysis with text output
scom-migrator analyze samples/Sample.Windows.Monitoring.xml

# Generate markdown report
scom-migrator analyze samples/Sample.Windows.Monitoring.xml --format markdown

# Save report to file
scom-migrator analyze samples/Sample.Windows.Monitoring.xml --output report.md --format markdown

# Verbose output with all component details
scom-migrator analyze samples/Sample.Windows.Monitoring.xml --verbose
```

### Generate Azure Monitor Templates

```bash
# Generate ARM templates
scom-migrator generate samples/Sample.Windows.Monitoring.xml --output-dir ./migration

# Generate Bicep templates
scom-migrator generate samples/Sample.Windows.Monitoring.xml --format bicep

# Customize workspace name
scom-migrator generate samples/Sample.Windows.Monitoring.xml --workspace-name my-workspace
```

### Inspect a Management Pack

```bash
# Show management pack structure
scom-migrator inspect samples/Sample.Windows.Monitoring.xml

# Show details for a specific component
scom-migrator details samples/Sample.Windows.Monitoring.xml --component Sample.Windows.Server.CPU.Monitor
```

### Scan Directory for Management Packs

```bash
# Scan current directory
scom-migrator scan .

# Scan recursively
scom-migrator scan /path/to/mps --recursive
```

## SCOM to Azure Monitor Mapping

The tool maps SCOM concepts to their Azure Monitor equivalents:

| SCOM Component | Azure Monitor Equivalent |
|----------------|-------------------------|
| Performance Counter Monitor | Metric Alert / Log Alert with Perf table |
| Windows Event Monitor | Log Alert with Event table |
| Service Monitor | Change Tracking / Log Alert |
| WMI-based Monitor | Log Alert with custom data |
| Script-based Monitor | Azure Functions + Custom Metrics |
| Discovery | Azure Resource Graph / VM Insights |
| Alert Rules | Scheduled Query Rules |
| Collection Rules | Data Collection Rules |

## Generated Artifacts

When you run the `generate` command, the tool creates:

```
azure-monitor-migration/
├── azuredeploy.json          # Complete ARM template
├── alert-rules.json          # Alert rules only
├── data-collection-rules.json # DCR configuration
├── main.bicep                 # Bicep template (optional)
├── migration-report.md        # Executive summary
└── migration-report.json      # Detailed JSON report
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Management    │────▶│     Parser      │────▶│   Management    │
│   Pack XML      │     │                 │     │   Pack Model    │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  ARM Templates  │◀────│    Generator    │◀────│    Analyzer     │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │     Mapper      │
                                                │                 │
                                                └─────────────────┘
```

## Programmatic Usage

```python
from scom_migrator import (
    ManagementPackParser,
    MigrationAnalyzer,
    ARMTemplateGenerator,
)

# Parse management pack
parser = ManagementPackParser("path/to/managementpack.xml")
mp = parser.parse()

# Analyze
analyzer = MigrationAnalyzer()
report = analyzer.analyze(mp)

# Generate executive summary
summary = analyzer.generate_executive_summary(report)
print(summary)

# Generate ARM templates
generator = ARMTemplateGenerator()
template = generator.generate_from_report(report)

# Export
generator.export_template(template, "azuredeploy.json")
```

## Migration Workflow

1. **Assessment Phase**
   - Run `scom-migrator analyze` on your management packs
   - Review the migration report for complexity and effort estimates
   - Identify components requiring manual intervention

2. **Planning Phase**
   - Review generated KQL queries and adjust as needed
   - Plan your Azure Monitor architecture (workspaces, DCRs, etc.)
   - Set up prerequisites (Azure Monitor Agent, Log Analytics workspace)

3. **Implementation Phase**
   - Deploy ARM templates to Azure
   - Configure Data Collection Rules on target machines
   - Create action groups for alert notifications

4. **Validation Phase**
   - Compare SCOM alerts with Azure Monitor alerts
   - Validate data collection and retention
   - Test alert firing and notification delivery

## Supported SCOM Components

### Monitors
- ✅ Unit Monitors (Performance, Event, Service)
- ✅ Aggregate Monitors (with limitations)
- ⚠️ Dependency Monitors (requires VM Insights)

### Rules
- ✅ Performance Collection Rules
- ✅ Event Collection Rules
- ✅ Alert Rules
- ⚠️ Script-based Rules (manual conversion)

### Discoveries
- ⚠️ WMI-based Discoveries
- ⚠️ Registry-based Discoveries
- ℹ️ Most discoveries map to Azure Resource Graph

### Data Sources
- ✅ Windows Performance Counters
- ✅ Windows Event Logs
- ✅ Windows Services
- ⚠️ WMI Queries
- ⚠️ Scripts/PowerShell
- ⚠️ Log Files
- ⚠️ SNMP

Legend: ✅ Full support | ⚠️ Partial/manual | ❌ Not supported

## Azure Monitor Prerequisites

Before deploying generated templates:

1. **Log Analytics Workspace**
   - Create or identify target workspace
   - Configure appropriate retention settings

2. **Azure Monitor Agent**
   - Deploy AMA to all target machines
   - For hybrid scenarios, enable Azure Arc

3. **Data Collection Rules**
   - Review and customize generated DCRs
   - Associate DCRs with target resources

4. **Action Groups**
   - Configure notification channels
   - Update email/SMS/webhook settings

## Configuration

### Environment Variables

```bash
# Azure authentication (for future direct deployment features)
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group"
export AZURE_TENANT_ID="your-tenant-id"
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

### Development Setup

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 src/
black src/ --check
mypy src/
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Microsoft SCOM documentation
- Azure Monitor documentation
- The Python community

## Support

- Create an issue for bug reports
- Discussions for feature requests
- Wiki for additional documentation

## Roadmap

- [ ] Direct Azure deployment via Azure SDK
- [ ] Support for sealed (.mp) management packs
- [ ] Web-based UI
- [ ] Batch processing of multiple MPs
- [ ] Custom mapping rules configuration
- [ ] Integration with Azure DevOps pipelines
