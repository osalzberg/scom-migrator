# Azure Static Web Apps - SCOM Migrator

## Project Structure

This project is configured for Azure Static Web Apps with:
- **Frontend**: Static HTML/CSS/JS in `/frontend`
- **API**: Python Azure Functions in `/api`

## Local Development

### Prerequisites
- Python 3.10+
- Azure Functions Core Tools v4
- Node.js (for Static Web Apps CLI)

### Install SWA CLI
```bash
npm install -g @azure/static-web-apps-cli
```

### Install Python dependencies
```bash
# Install API dependencies
cd api
pip install -r requirements.txt
cd ..

# Install core library
pip install -e .
```

### Run Locally
```bash
swa start frontend --api-location api
```

This will start:
- Frontend at http://localhost:4280
- API at http://localhost:7071/api

## Deployment

### Option 1: GitHub Actions (Recommended)
1. Push to GitHub
2. Create a Static Web App in Azure Portal
3. Connect to your GitHub repo
4. Azure will auto-configure GitHub Actions

### Option 2: Azure CLI
```bash
# Login to Azure
az login

# Create resource group (if needed)
az group create --name OrensResourceGroup --location eastus

# Create Static Web App
az staticwebapp create \
  --name scom-migrator \
  --resource-group OrensResourceGroup \
  --source https://github.com/osalzberg/scom-migrator \
  --location "eastus2" \
  --branch main \
  --app-location "/frontend" \
  --api-location "/api" \
  --output-location "/" \
  --login-with-github
```

### Option 3: SWA CLI Deploy
```bash
swa deploy --deployment-token <YOUR_DEPLOYMENT_TOKEN>
```

## Configuration

- `staticwebapp.config.json` - Route configuration and security headers
- `api/host.json` - Azure Functions host configuration
- `api/local.settings.json` - Local development settings

## API Endpoints

- `POST /api/analyze` - Upload and analyze a management pack
- `GET /api/download/{type}` - Download artifacts (arm, dcr, report)
