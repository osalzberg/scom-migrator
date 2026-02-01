#!/usr/bin/env python3
"""
Simple script to run the SCOM Migrator web interface
"""

from src.scom_migrator.web import run_server

if __name__ == '__main__':
    print("\n" + "="*70)
    print("Starting SCOM to Azure Monitor Migration Tool Web Interface")
    print("="*70)
    print("\nThe server will start on port 8080")
    print("Open your browser to: http://localhost:8080")
    print("\nPress Ctrl+C to stop the server")
    print("="*70 + "\n")
    
    try:
        run_server(host='127.0.0.1', port=8080, debug=False)
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\n\nError starting server: {e}")
        print("\nTry a different port:")
        print("  python run_web.py --port 5001")