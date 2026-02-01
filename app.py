"""
WSGI entry point for Azure App Service
"""
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scom_migrator.web import app

# For Azure App Service
application = app

if __name__ == '__main__':
    app.run()
