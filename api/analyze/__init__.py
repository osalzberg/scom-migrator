"""
Analyze endpoint - Parse and analyze SCOM Management Pack
"""

import azure.functions as func
import json
import logging
import sys
import os

# Add parent directory to path for imports
api_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, api_dir)

try:
    from scom_migrator.parser import ManagementPackParser
    from scom_migrator.analyzer import MigrationAnalyzer
    from scom_migrator.generator import ARMTemplateGenerator
    IMPORT_ERROR = None
except Exception as e:
    IMPORT_ERROR = str(e)
    ManagementPackParser = None
    MigrationAnalyzer = None
    ARMTemplateGenerator = None


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Analyze an uploaded management pack."""
    logging.info('Processing analyze request')
    
    # Check for import errors
    if IMPORT_ERROR:
        return func.HttpResponse(
            json.dumps({'error': f'Import error: {IMPORT_ERROR}'}),
            status_code=500,
            mimetype='application/json'
        )
    
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
        if ext not in ['xml', 'mp', 'mpb']:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid file type. Please upload .xml, .mp, or .mpb file'}),
                status_code=400,
                mimetype='application/json'
            )
        
        # Read file content as bytes
        content = file.read()
        logging.info(f'File uploaded: {filename}, size: {len(content)} bytes, first 20 bytes: {content[:20]}')
        
        # Parse and analyze
        parser = ManagementPackParser(content=content)
        mp = parser.parse()
        logging.info(f'Parsed: {mp.total_monitors} monitors, {mp.total_rules} rules, {len(mp.discoveries)} discoveries')
        
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(mp)
        logging.info(f'Analyzed: {report.total_components} components')
        
        # Generate templates - reuse intermediate results to avoid double work
        generator = ARMTemplateGenerator()
        arm_template = generator.generate_from_report(report)
        dcr_template = generator.generate_data_collection_rules(report)
        workbook_template = generator.generate_workbook(report)
        custom_log_dcr = generator.generate_custom_log_dcr(report)
        complete_template = generator.generate_complete_deployment(
            report,
            prebuilt_arm=arm_template,
            prebuilt_dcr=dcr_template,
            prebuilt_workbook=workbook_template,
            prebuilt_custom_log_dcr=custom_log_dcr,
        )
        logging.info('Generated all templates')
        
        # Get stats
        stats = analyzer.get_summary_stats(report)
        
        # Return results - exclude raw_xml to reduce response size
        result = report.model_dump(exclude={'mappings': {'__all__': {'recommendations': {'__all__': {'arm_template_snippet'}}}}})
        result['stats'] = stats
        result['_arm_template'] = arm_template
        result['_dcr_template'] = dcr_template
        result['_workbook_template'] = workbook_template
        result['_custom_log_dcr'] = custom_log_dcr
        result['_complete_template'] = complete_template
        
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
