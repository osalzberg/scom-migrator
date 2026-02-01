"""
Download endpoint - Download generated artifacts
"""

import azure.functions as func
import json
import logging


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Download generated artifacts."""
    artifact_type = req.route_params.get('artifact_type')
    logging.info(f'Processing download request for: {artifact_type}')
    
    # Note: In a stateless function, we can't persist the analysis between calls
    # The frontend should include the data in the request or we need to use storage
    return func.HttpResponse(
        json.dumps({'error': 'Download not available in serverless mode. Use the data from the analyze response.'}),
        status_code=400,
        mimetype='application/json'
    )
