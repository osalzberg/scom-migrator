"""
Analyze endpoint - Parse and analyze SCOM Management Pack
"""

import azure.functions as func
import json
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scom_migrator.parser import ManagementPackParser
from scom_migrator.analyzer import MigrationAnalyzer
from scom_migrator.generator import ARMTemplateGenerator


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Analyze an uploaded management pack."""
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
        
        # Generate templates for download (store in app state or session - simplified here)
        generator = ARMTemplateGenerator()
        arm_template = generator.generate_from_report(report)
        dcr_template = generator.generate_data_collection_rules(report)
        
        # Get stats
        stats = analyzer.get_summary_stats(report)
        
        # Return results
        result = report.model_dump()
        result['stats'] = stats
        result['_arm_template'] = arm_template
        result['_dcr_template'] = dcr_template
        
        return func.HttpResponse(
            json.dumps(result, default=str),
            mimetype='application/json'
        )
        
    except Exception as e:
        logging.error(f'Error analyzing file: {str(e)}')
        import traceback
        logging.error(traceback.format_exc())
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json'
        )
