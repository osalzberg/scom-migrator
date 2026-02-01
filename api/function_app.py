"""
Azure Functions API for SCOM to Azure Monitor Migration Tool

This module provides serverless API endpoints for Static Web Apps.
"""

import azure.functions as func
import json
import logging

from scom_migrator.parser import ManagementPackParser
from scom_migrator.analyzer import MigrationAnalyzer
from scom_migrator.generator import ARMTemplateGenerator

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Store the last analysis for download
last_analysis = {}


@app.route(route="analyze", methods=["POST"])
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    """Analyze an uploaded management pack."""
    global last_analysis
    logging.info('Processing analyze request')
    
    try:
        # Get the uploaded file
        file = req.files.get('file')
        if not file:
            return func.HttpResponse(
                json.dumps({'error': 'No file provided'}),
                status_code=400,
                mimetype='application/json'
            )
        
        filename = file.filename
        if not filename:
            return func.HttpResponse(
                json.dumps({'error': 'No file selected'}),
                status_code=400,
                mimetype='application/json'
            )
        
        # Check file extension
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext not in ['xml', 'mp']:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid file type. Please upload .xml or .mp file'}),
                status_code=400,
                mimetype='application/json'
            )
        
        # Read file content
        content = file.read()
        
        # Parse and analyze
        parser = ManagementPackParser(content=content)
        mp = parser.parse()
        
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(mp)
        
        # Generate templates for download
        generator = ARMTemplateGenerator()
        arm_template = generator.generate_from_report(report)
        dcr_template = generator.generate_data_collection_rules(report)
        
        # Store for download
        last_analysis = {
            'report': report,
            'arm_template': arm_template,
            'dcr_template': dcr_template,
        }
        
        # Get stats
        stats = analyzer.get_summary_stats(report)
        
        # Return results
        result = report.model_dump()
        result['stats'] = stats
        
        return func.HttpResponse(
            json.dumps(result, default=str),
            mimetype='application/json'
        )
        
    except Exception as e:
        logging.error(f'Error analyzing file: {str(e)}')
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json'
        )


@app.route(route="download/{artifact_type}", methods=["GET"])
def download(req: func.HttpRequest) -> func.HttpResponse:
    """Download generated artifacts."""
    global last_analysis
    
    artifact_type = req.route_params.get('artifact_type')
    logging.info(f'Processing download request for: {artifact_type}')
    
    if not last_analysis:
        return func.HttpResponse(
            json.dumps({'error': 'No analysis available'}),
            status_code=400,
            mimetype='application/json'
        )
    
    try:
        if artifact_type == 'arm':
            content = json.dumps(last_analysis['arm_template'], indent=2)
            filename = 'azuredeploy.json'
        elif artifact_type == 'dcr':
            content = json.dumps(last_analysis['dcr_template'], indent=2)
            filename = 'data-collection-rules.json'
        elif artifact_type == 'report':
            content = last_analysis['report'].model_dump_json(indent=2)
            filename = 'migration-report.json'
        else:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid artifact type'}),
                status_code=400,
                mimetype='application/json'
            )
        
        return func.HttpResponse(
            content,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )
        
    except Exception as e:
        logging.error(f'Error downloading artifact: {str(e)}')
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json'
        )
