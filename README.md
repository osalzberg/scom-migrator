# 🔄 SCOM to Azure Monitor Migration Tool

[![Azure Static Web Apps](https://img.shields.io/badge/Azure-Static%20Web%20Apps-0078d4?logo=microsoft-azure)](https://icy-wave-02c4e6b03.2.azurestaticapps.net)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Discussions](https://img.shields.io/badge/Discussions-Join%20the%20Community-blue?logo=github)](https://github.com/osalzberg/scom-migrator/discussions)

A comprehensive web-based tool for migrating **System Center Operations Manager (SCOM)** Management Packs to **Azure Monitor**. Upload your SCOM MP XML files and get instant analysis, migration recommendations, and deployable ARM templates.

## 🌐 Try It Now

**[Launch the Web Tool →](https://icy-wave-02c4e6b03.2.azurestaticapps.net)**

No installation required - just upload your Management Pack XML and get results instantly.

---

## 💬 Community & Feedback

We'd love to hear from you! This is a community-driven project.

- **[💡 Share Ideas & Feedback](https://github.com/osalzberg/scom-migrator/discussions)** - Join the discussion
- **[🐛 Report Issues](https://github.com/osalzberg/scom-migrator/issues/new/choose)** - Bug reports and feature requests
- **[⭐ Star the Repo](https://github.com/osalzberg/scom-migrator)** - Show your support!

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📊 **Instant Analysis** | Upload SCOM MP XML files and get migration readiness scores |
| 🎯 **Smart Recommendations** | Intelligent mapping of SCOM components to Azure Monitor equivalents |
| 📋 **ARM Templates** | Auto-generate deployable Azure Resource Manager templates |
| 🔍 **KQL Queries** | Generate Log Analytics queries for your monitoring scenarios |
| 📥 **Multiple Exports** | Download ARM templates, DCR templates, or CSV reports |
| 🔒 **Secure** | Files processed in Azure Functions, no data stored |

---

## 🚀 Quick Start

### Web Interface (Recommended)

1. Go to [https://icy-wave-02c4e6b03.2.azurestaticapps.net](https://icy-wave-02c4e6b03.2.azurestaticapps.net)
2. Drag & drop your SCOM Management Pack XML file
3. Review the migration analysis and recommendations
4. Download ARM templates and deploy to Azure

### CLI (For Automation)

```bash
# Install
pip install -e .

# Analyze a Management Pack
scom-migrator analyze your-management-pack.xml --format markdown

# Generate ARM templates
scom-migrator generate your-management-pack.xml --output-dir ./migration
```

---

## 📊 What Gets Migrated

| SCOM Component | Azure Monitor Equivalent |
|----------------|--------------------------|
| Unit Monitors | Log Analytics Scheduled Query Alerts |
| Performance Rules | Data Collection Rules (DCR) + Perf counters |
| Event Rules | DCR + Windows Event collection |
| Service Monitors | Event ID 7036 alerts (Service Control Manager) |
| Script Monitors | Azure Functions / Automation Runbooks |
| Discoveries | Azure Resource Graph / VM Insights |

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   SCOM MP XML   │ ──▶ │  Parser/Mapper  │ ──▶ │  ARM Templates  │
│   (Upload)      │     │  (Analysis)     │     │  (Download)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │ Recommendations │
                        │ + KQL Queries   │
                        └─────────────────┘
```

**Tech Stack:**
- **Frontend**: HTML5, Bootstrap 5, Vanilla JavaScript
- **Backend**: Python 3.10+, Flask, Azure Functions
- **Hosting**: Azure Static Web Apps
- **Security**: defusedxml (XXE protection), XSS escaping

---

## 📦 Deployment to Azure

After downloading the ARM templates:

### Azure Portal
1. Go to Azure Portal → Deploy a custom template
2. Click "Build your own template in the editor"
3. Paste the downloaded ARM template
4. Fill in parameters and deploy

### Azure CLI
```bash
az deployment group create \
  --resource-group YourResourceGroup \
  --template-file azuredeploy.json \
  --parameters workspaceName=your-workspace actionGroupEmail=alerts@company.com
```

### PowerShell
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "YourResourceGroup" `
  -TemplateFile "azuredeploy.json" `
  -workspaceName "your-workspace"
```

---

## 🛠️ Local Development

```bash
# Clone the repo
git clone https://github.com/osalzberg/scom-migrator.git
cd scom-migrator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run locally with SWA CLI
npm install -g @azure/static-web-apps-cli
swa start frontend --api-location api
```

---

## 📁 Project Structure

```
scom-migrator/
├── frontend/           # Web UI (HTML/JS/CSS)
│   ├── index.html     # Main migration tool
│   └── portfolio.html # Project showcase
├── api/               # Azure Functions API
│   └── scom_migrator/ # Core Python package
├── src/               # CLI version
└── samples/           # Sample MP files for testing
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

- [SCOM MP Builder](https://agreeable-dune-0dc5ed30f.4.azurestaticapps.net/creator.html) - Create SCOM Management Packs without XML knowledge
- [Azure Monitor Documentation](https://docs.microsoft.com/azure/azure-monitor/)

---

## 👤 Author

**Oren Salzberg**

- GitHub: [@osalzberg](https://github.com/osalzberg)
- Project Portfolio: [View All Tools](https://icy-wave-02c4e6b03.2.azurestaticapps.net/portfolio.html)

---

<p align="center">
  <sub>Built with ❤️ for the Azure & SCOM community</sub>
</p>
