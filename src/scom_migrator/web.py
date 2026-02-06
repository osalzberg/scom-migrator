"""
Web Server for SCOM to Azure Monitor Migration Tool

Provides a web interface for uploading and analyzing management packs.
"""

import json
import tempfile
import os
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify, render_template_string, send_file
from werkzeug.utils import secure_filename

from .parser import ManagementPackParser
from .analyzer import MigrationAnalyzer
from .generator import ARMTemplateGenerator

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

ALLOWED_EXTENSIONS = {'xml', 'mp'}

# Store the last analysis for download
last_analysis = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCOM to Azure Monitor Migration Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --azure-blue: #0078d4;
            --azure-dark: #004578;
            --azure-light: #50a0e0;
            --success-green: #107c10;
            --warning-orange: #ff8c00;
            --error-red: #e81123;
            --microsoft-gray: #f3f2f1;
            --dark-gray: #323130;
            --light-gray: #faf9f8;
            --border-gray: #edebe9;
            --text-gray: #605e5c;
            --gradient-1: linear-gradient(135deg, #0078d4 0%, #004578 100%);
            --gradient-accent: linear-gradient(135deg, #50a0e0 0%, #0078d4 100%);
            --card-shadow: 0 4px 12px rgba(0,0,0,0.08);
            --hover-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }
        
        * {
            font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
        }
        
        body {
            background: #f3f2f1;
            min-height: 100vh;
            background-attachment: fixed;
        }
        
        .main-container {
            padding: 2rem 0;
            animation: fadeIn 0.6s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .card {
            border: none;
            border-radius: 20px;
            box-shadow: var(--card-shadow);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            box-shadow: var(--hover-shadow);
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--azure-blue), var(--azure-dark));
            color: white;
            border-radius: 20px 20px 0 0 !important;
            padding: 2rem;
            border: none;
        }
        
        .card-header h4 {
            font-weight: 600;
            margin: 0;
        }
        
        .upload-zone {
            border: 3px dashed #cbd5e0;
            border-radius: 15px;
            padding: 4rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            position: relative;
            overflow: hidden;
        }
        
        .upload-zone::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0,120,212,0.1), transparent);
            transition: left 0.5s ease;
        }
        
        .upload-zone:hover::before {
            left: 100%;
        }
        
        .upload-zone:hover, .upload-zone.dragover {
            border-color: var(--azure-blue);
            background: linear-gradient(135deg, #e6f3ff 0%, #cce5ff 100%);
            transform: scale(1.02);
        }
        
        .upload-zone.dragover {
            border-style: solid;
            box-shadow: 0 0 30px rgba(0,120,212,0.3);
        }
        
        .upload-zone i {
            font-size: 5rem;
            color: var(--azure-blue);
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .btn-azure {
            background: linear-gradient(135deg, var(--azure-blue), var(--azure-light));
            border: none;
            color: white;
            font-weight: 500;
            padding: 0.75rem 2rem;
            border-radius: 10px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,120,212,0.3);
        }
        
        .btn-azure:hover {
            background: linear-gradient(135deg, var(--azure-dark), var(--azure-blue));
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,120,212,0.4);
            color: white;
        }
        
        .btn-azure:active {
            transform: translateY(0);
        }
        
        .result-section {
            display: none;
            animation: slideIn 0.5s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-30px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .stat-card {
            background: linear-gradient(135deg, #ffffff 0%, #f7fafc 100%);
            border-radius: 15px;
            padding: 2rem;
            text-align: center;
            transition: all 0.3s ease;
            border: 1px solid #e2e8f0;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-3);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            font-size: 3rem;
            font-weight: 700;
            color: var(--azure-dark);
            margin: 0;
            background: var(--gradient-3);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .stat-card small {
            color: #64748b;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.75rem;
        }
        
        .complexity-simple { color: #107c10; }
        .complexity-moderate { color: #ff8c00; }
        .complexity-complex { color: #e81123; }
        .complexity-manual { color: #8b5cf6; }
        
        .mapping-card {
            border-left: 4px solid var(--azure-blue);
            margin-bottom: 1rem;
            transition: all 0.3s ease;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .mapping-card:hover {
            transform: translateX(8px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .kql-code {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 1.5rem;
            border-radius: 10px;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .loading {
            display: none;
        }
        
        .spinner-border {
            width: 4rem;
            height: 4rem;
            border-width: 0.4rem;
        }
        
        .badge-target {
            font-size: 0.75rem;
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            font-weight: 500;
        }
        
        .prereq-list {
            list-style: none;
            padding: 0;
        }
        
        .prereq-list li {
            padding: 0.75rem 0;
            border-bottom: 1px solid #e2e8f0;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
        }
        
        .prereq-list li:hover {
            padding-left: 10px;
            background: #f7fafc;
        }
        
        .prereq-list li:before {
            content: "✓";
            color: var(--success-green);
            margin-right: 0.75rem;
            font-weight: bold;
            font-size: 1.2rem;
        }
        
        #fileInput {
            display: none;
        }
        
        label[for="fileInput"] {
            cursor: pointer;
        }
        
        .alert-info {
            background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%);
            border: none;
            border-left: 4px solid #0ea5e9;
            border-radius: 10px;
        }
        
        .card-header.bg-light {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%) !important;
            color: #1e293b;
            font-weight: 600;
        }
        
        .card.border-success {
            border: 2px solid var(--success-green) !important;
        }
        
        .card.border-success .card-header {
            background: linear-gradient(135deg, #107c10, #0b5c0b) !important;
        }
        
        .card.border-warning {
            border: 2px solid var(--warning-orange) !important;
        }
        
        .card.border-warning .card-header {
            background: linear-gradient(135deg, #ff8c00, #cc7000) !important;
        }
        
        .btn-outline-primary {
            border-color: var(--azure-blue);
            color: var(--azure-blue);
            transition: all 0.3s ease;
        }
        
        .btn-outline-primary:hover {
            background: var(--azure-blue);
            border-color: var(--azure-blue);
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,120,212,0.3);
        }
        
        details summary {
            cursor: pointer;
            user-select: none;
            padding: 0.5rem;
            border-radius: 5px;
            transition: background 0.2s ease;
        }
        
        details summary:hover {
            background: #f1f5f9;
        }
        
        details[open] summary {
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        
        .progress-bar-animated {
            animation: progress-bar-stripes 1s linear infinite;
        }
        
        @keyframes progress-bar-stripes {
            0% { background-position: 0 0; }
            100% { background-position: 40px 0; }
        }
        
        .footer-text {
            text-align: center;
            margin-top: 2rem;
            color: white;
            opacity: 0.85;
            font-size: 0.875rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .btn-group .btn {
            border-radius: 8px;
            margin: 0 2px;
            transition: all 0.2s ease;
        }
        
        .btn-group .btn.active {
            background: var(--azure-blue);
            color: white;
            box-shadow: 0 2px 8px rgba(0,120,212,0.3);
        }
        
        @media (max-width: 768px) {
            .stat-card h3 {
                font-size: 2rem;
            }
            
            .upload-zone {
                padding: 2rem 1rem;
            }
            
            .upload-zone i {
                font-size: 3rem;
            }
        }
    </style>
</head>
<body>
    <div class="container main-container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-cloud-arrow-up me-3" style="font-size: 2.5rem;"></i>
                            <div>
                                <h4 class="mb-1">SCOM to Azure Monitor Migration Tool</h4>
                                <small class="opacity-85">Upload a Management Pack to analyze and generate migration artifacts</small>
                            </div>
                        </div>
                    </div>
                    <div class="card-body p-4">
                        <!-- Upload Section -->
                        <div id="uploadSection">
                            <div class="upload-zone" id="dropZone">
                                <i class="bi bi-file-earmark-arrow-up mb-3"></i>
                                <h5 class="mt-3 mb-2">Drop Management Pack Here</h5>
                                <p class="text-muted mb-4">or click the button below</p>
                                <label for="fileInput" class="btn btn-azure btn-lg">
                                    <i class="bi bi-folder2-open me-2"></i>Browse Files
                                </label>
                                <p class="small text-muted mt-4 mb-0">
                                    <i class="bi bi-info-circle me-1"></i>
                                    Supports .xml and .mp files (max 50MB)
                                </p>
                            </div>
                            <input type="file" id="fileInput" accept=".xml,.mp" onchange="handleFileSelect(event)">
                            
                            <div class="mt-3" id="selectedFile" style="display: none;">
                                <div class="alert alert-info d-flex align-items-center">
                                    <i class="bi bi-file-earmark-code me-2 fs-4"></i>
                                    <span id="fileName" class="flex-grow-1"></span>
                                    <button type="button" class="btn-close" onclick="clearFile()"></button>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 mt-4">
                                <button class="btn btn-azure btn-lg" id="analyzeBtn" onclick="analyzeFile()" disabled>
                                    <i class="bi bi-search me-2"></i>Analyze Management Pack
                                </button>
                            </div>
                        </div>
                        
                        <!-- Loading Section -->
                        <div class="loading text-center py-5" id="loadingSection">
                            <div class="spinner-border text-primary mb-4" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <h5 class="mb-2">Analyzing Management Pack...</h5>
                            <p class="text-muted">Parsing XML, analyzing components, and generating recommendations</p>
                        </div>
                        
                        <!-- Results Section -->
                        <div class="result-section" id="resultSection">
                            <div class="d-flex justify-content-between align-items-center mb-4">
                                <h5 class="mb-0">
                                    <i class="bi bi-clipboard-data me-2"></i>
                                    Analysis Results
                                </h5>
                                <button class="btn btn-outline-secondary btn-sm" onclick="resetForm()">
                                    <i class="bi bi-arrow-left me-1"></i>Analyze Another
                                </button>
                            </div>
                            
                            <!-- MP Info -->
                            <div class="alert alert-info mb-4">
                                <h6 class="mb-1 fw-bold" id="mpName"></h6>
                                <small id="mpVersion"></small>
                            </div>
                            
                            <!-- Stats -->
                            <div class="row g-3 mb-4">
                                <div class="col-md-4 col-sm-6">
                                    <div class="stat-card">
                                        <h3 id="totalComponents" style="color: #0078d4;">0</h3>
                                        <small>Total Components</small>
                                    </div>
                                </div>
                                <div class="col-md-4 col-sm-6">
                                    <div class="stat-card">
                                        <h3 id="migratableCount" style="color: #107c10;">0</h3>
                                        <small>Easily Migratable</small>
                                    </div>
                                </div>
                                <div class="col-md-4 col-sm-6">
                                    <div class="stat-card">
                                        <h3 id="manualCount" style="color: #ff8c00;">0</h3>
                                        <small>Manual Review</small>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Complexity Breakdown -->
                            <div class="card mb-4">
                                <div class="card-header bg-light">
                                    <h6 class="mb-0"><i class="bi bi-bar-chart me-2"></i>Complexity Breakdown</h6>
                                </div>
                                <div class="card-body">
                                    <div class="row text-center" id="complexityBreakdown">
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Recommendations -->
                            <div class="card mb-4">
                                <div class="card-header bg-light">
                                    <h6 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Key Recommendations</h6>
                                </div>
                                <div class="card-body">
                                    <div id="recommendations"></div>
                                </div>
                            </div>
                            
                            <!-- Prerequisites -->
                            <div class="card mb-4">
                                <div class="card-header bg-light">
                                    <h6 class="mb-0"><i class="bi bi-check2-square me-2"></i>Prerequisites</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="prereq-list" id="prerequisites"></ul>
                                </div>
                            </div>
                            
                            <!-- Easily Migratable Components -->
                            <div class="card mb-4 border-success" id="easyMigrationCard" style="display: none;">
                                <div class="card-header bg-success text-white">
                                    <h6 class="mb-0"><i class="bi bi-check-circle me-2"></i>Easily Migratable Components (Quick Wins)</h6>
                                </div>
                                <div class="card-body">
                                    <p class="text-muted small mb-3">
                                        <i class="bi bi-info-circle me-1"></i>
                                        These components can be migrated with minimal effort. Start here for quick wins!
                                    </p>
                                    <div id="easyMappings"></div>
                                </div>
                            </div>
                            
                            <!-- Components Requiring Manual Review -->
                            <div class="card mb-4 border-warning" id="manualReviewCard" style="display: none;">
                                <div class="card-header bg-warning text-white">
                                    <h6 class="mb-0"><i class="bi bi-exclamation-triangle me-2"></i>Components Requiring Manual Review</h6>
                                </div>
                                <div class="card-body">
                                    <p class="text-muted small mb-3">
                                        <i class="bi bi-info-circle me-1"></i>
                                        These components need manual analysis and custom implementation.
                                    </p>
                                    <div id="manualMappings"></div>
                                </div>
                            </div>
                            
                            <!-- All Component Mappings -->
                            <div class="card mb-4">
                                <div class="card-header bg-light d-flex justify-content-between align-items-center flex-wrap">
                                    <h6 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>All Component Mappings</h6>
                                    <div class="btn-group btn-group-sm mt-2 mt-md-0">
                                        <button class="btn btn-outline-secondary active" onclick="filterMappings('all')">All</button>
                                        <button class="btn btn-outline-secondary" onclick="filterMappings('Monitor')">Monitors</button>
                                        <button class="btn btn-outline-secondary" onclick="filterMappings('Rule')">Rules</button>
                                        <button class="btn btn-outline-secondary" onclick="filterMappings('Discovery')">Discoveries</button>
                                    </div>
                                </div>
                                <div class="card-body" style="max-height: 500px; overflow-y: auto;">
                                    <div id="mappings"></div>
                                </div>
                            </div>
                            
                            <!-- Download Section -->
                            <div class="card">
                                <div class="card-header bg-light">
                                    <h6 class="mb-0"><i class="bi bi-download me-2"></i>Download Migration Artifacts</h6>
                                </div>
                                <div class="card-body">
                                    <div class="alert alert-warning mb-3" style="background: linear-gradient(135deg, #fff3cd 0%, #ffe5a0 100%); border: 2px solid #ffc107; border-radius: 10px;">
                                        <div class="d-flex align-items-center">
                                            <i class="bi bi-exclamation-triangle-fill me-3 fs-4" style="color: #ff8c00;"></i>
                                            <div>
                                                <strong>⚠️ Testing Status:</strong>
                                                <p class="mb-0 small mt-1">
                                                    Download functionality has <strong>not been fully tested</strong>. 
                                                    Please verify the downloaded artifacts before using them in production environments.
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row g-3">
                                        <div class="col-md-4">
                                            <div class="d-grid">
                                                <button class="btn btn-outline-primary" onclick="downloadArtifact('arm')" title="Not fully tested - verify before use">
                                                    <i class="bi bi-filetype-json me-2"></i>ARM Template
                                                    <span class="badge bg-warning text-dark ms-2" style="font-size: 0.65rem;">UNTESTED</span>
                                                </button>
                                            </div>
                                        </div>
                                        <div class="col-md-4">
                                            <div class="d-grid">
                                                <button class="btn btn-outline-primary" onclick="downloadArtifact('report')" title="Not fully tested - verify before use">
                                                    <i class="bi bi-file-earmark-text me-2"></i>Full Report (JSON)
                                                    <span class="badge bg-warning text-dark ms-2" style="font-size: 0.65rem;">UNTESTED</span>
                                                </button>
                                            </div>
                                        </div>
                                        <div class="col-md-4">
                                            <div class="d-grid">
                                                <button class="btn btn-outline-primary" onclick="downloadArtifact('dcr')" title="Not fully tested - verify before use">
                                                    <i class="bi bi-gear me-2"></i>Data Collection Rules
                                                    <span class="badge bg-warning text-dark ms-2" style="font-size: 0.65rem;">UNTESTED</span>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- About the Author -->
                <div class="card mt-4" style="background: linear-gradient(135deg, rgba(255,255,255,0.98) 0%, rgba(240,248,255,0.98) 100%);">
                    <div class="card-body p-4">
                        <h6 class="text-primary mb-3">
                            <i class="bi bi-person-badge me-2"></i>
                            About the Author
                        </h6>
                        <div class="d-flex align-items-start">
                            <div class="flex-grow-1">
                                <h6 class="mb-1 fw-bold">Oren Salzberg</h6>
                                <p class="small text-muted mb-2">
                                    <i class="bi bi-briefcase me-1"></i>
                                    Product Manager - Microsoft Azure Log Analytics Team
                                </p>
                                <p class="small mb-2">
                                    Oren is a Product Manager in the Microsoft Azure Log Analytics team with extensive experience in IT monitoring 
                                    and operations management. As a former SCOM Premier Field Engineer, he brings deep expertise in System Center 
                                    Operations Manager and enterprise monitoring solutions to help organizations optimize their IT infrastructure.
                                </p>
                                <p class="small mb-0">
                                    <i class="bi bi-linkedin me-1" style="color: #0077b5;"></i>
                                    <a href="https://www.linkedin.com/in/oren-salzberg-4b827b57/" target="_blank" rel="noopener noreferrer" 
                                       class="text-decoration-none" style="color: #0077b5;">
                                        Connect on LinkedIn
                                    </a>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Disclaimer -->
                <div class="mt-4 p-3" style="background: rgba(255,255,255,0.7); border-radius: 8px;">
                    <p class="mb-2" style="font-size: 0.7rem; color: #8a8886; line-height: 1.4;">
                        <strong style="color: #605e5c;">Disclaimer:</strong> 
                        This web application is provided as-is for informational and educational purposes. 
                        The use of this application and any generated ARM templates, migration reports, or artifacts is at your own risk. 
                        This tool is not officially supported or endorsed by Microsoft Corporation. Microsoft Corporation assumes no 
                        responsibility or liability for the use of this tool or any content generated through it. Users are responsible 
                        for testing and validating all generated templates and configurations in their environment before production deployment.
                    </p>
                    <p class="mb-0" style="font-size: 0.65rem; color: #a19f9d;">
                        <strong>Trademarks:</strong> Microsoft, Azure, Azure Monitor, System Center Operations Manager (SCOM), 
                        Windows, and other product names referenced are trademarks or registered trademarks of Microsoft Corporation 
                        in the United States and/or other countries.
                    </p>
                </div>
                
                <div class="footer-text text-center" style="margin-top: 2rem; margin-bottom: 2rem;">
                    <p class="mb-1" style="color: #605e5c;">
                        <i class="bi bi-shield-check me-1"></i>
                        SCOM to Azure Monitor Migration Tool v1.0.0
                    </p>
                    <small style="color: #8a8886;">Community Tool • Not Officially Supported</small>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedFile = null;
        let analysisResult = null;
        let allMappings = [];
        
        // Wait for DOM to be ready
        document.addEventListener('DOMContentLoaded', function() {
            const dropZone = document.getElementById('dropZone');
            
            if (!dropZone) {
                console.error('Drop zone not found!');
                return;
            }
            
            // Prevent default drag behaviors on the whole document
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                document.body.addEventListener(eventName, function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                }, false);
            });
            
            // Highlight drop zone when dragging over it
            dropZone.addEventListener('dragenter', function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            }, false);
            
            dropZone.addEventListener('dragover', function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            }, false);
            
            dropZone.addEventListener('dragleave', function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            }, false);
            
            dropZone.addEventListener('drop', function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
                
                const dt = e.dataTransfer;
                if (dt && dt.files && dt.files.length > 0) {
                    handleFile(dt.files[0]);
                }
            }, false);
        });
        
        function handleFileSelect(event) {
            const files = event.target.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        }
        
        function handleFile(file) {
            const ext = file.name.split('.').pop().toLowerCase();
            if (!['xml', 'mp'].includes(ext)) {
                alert('Please select a valid Management Pack file (.xml or .mp)');
                return;
            }
            
            selectedFile = file;
            document.getElementById('fileName').textContent = file.name + ' (' + formatFileSize(file.size) + ')';
            document.getElementById('selectedFile').style.display = 'block';
            document.getElementById('analyzeBtn').disabled = false;
        }
        
        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        
        function clearFile() {
            selectedFile = null;
            document.getElementById('fileInput').value = '';
            document.getElementById('selectedFile').style.display = 'none';
            document.getElementById('analyzeBtn').disabled = true;
        }
        
        function analyzeFile() {
            if (!selectedFile) return;
            
            const formData = new FormData();
            formData.append('file', selectedFile);
            
            document.getElementById('uploadSection').style.display = 'none';
            document.getElementById('loadingSection').style.display = 'block';
            
            fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loadingSection').style.display = 'none';
                
                if (data.error) {
                    alert('Error: ' + data.error);
                    document.getElementById('uploadSection').style.display = 'block';
                    return;
                }
                
                analysisResult = data;
                displayResults(data);
            })
            .catch(error => {
                document.getElementById('loadingSection').style.display = 'none';
                document.getElementById('uploadSection').style.display = 'block';
                alert('Error analyzing file: ' + error);
            });
        }
        
        function displayResults(data) {
            document.getElementById('resultSection').style.display = 'block';
            
            // MP Info
            document.getElementById('mpName').textContent = data.management_pack.display_name || data.management_pack.name;
            document.getElementById('mpVersion').textContent = 'Version: ' + data.management_pack.version;
            
            // Stats with animation
            animateValue('totalComponents', 0, data.total_components, 1000);
            animateValue('migratableCount', 0, data.migratable_components, 1000);
            animateValue('manualCount', 0, data.requires_manual_review, 1000);
            
            // Complexity breakdown
            const stats = data.stats || {};
            const complexityDiv = document.getElementById('complexityBreakdown');
            const breakdown = stats.complexity_breakdown || {};
            complexityDiv.innerHTML = `
                <div class="col-3">
                    <h4 class="complexity-simple">${breakdown.simple || 0}</h4>
                    <small>Simple</small>
                </div>
                <div class="col-3">
                    <h4 class="complexity-moderate">${breakdown.moderate || 0}</h4>
                    <small>Moderate</small>
                </div>
                <div class="col-3">
                    <h4 class="complexity-complex">${breakdown.complex || 0}</h4>
                    <small>Complex</small>
                </div>
                <div class="col-3">
                    <h4 class="complexity-manual">${breakdown.manual || 0}</h4>
                    <small>Manual</small>
                </div>
            `;
            
            // Recommendations
            const recsDiv = document.getElementById('recommendations');
            recsDiv.innerHTML = data.overall_recommendations.map(rec => 
                `<div class="mb-2"><i class="bi bi-arrow-right-circle me-2 text-primary"></i>${rec}</div>`
            ).join('');
            
            // Prerequisites
            const prereqList = document.getElementById('prerequisites');
            prereqList.innerHTML = data.prerequisites.slice(0, 10).map(p => 
                `<li>${p}</li>`
            ).join('');
            
            // Mappings - separate easy vs manual
            allMappings = data.mappings;
            displayMappings(allMappings);
            
            // Display easy migrations separately
            const easyMappings = allMappings.filter(m => 
                m.migration_complexity === 'Simple' || m.migration_complexity === 'Moderate'
            );
            const manualMappings = allMappings.filter(m => 
                m.migration_complexity === 'ManualRequired' || m.migration_complexity === 'Complex'
            );
            
            if (easyMappings.length > 0) {
                document.getElementById('easyMigrationCard').style.display = 'block';
                document.getElementById('easyMappings').innerHTML = easyMappings.map(m => createMappingCard(m, true)).join('');
            }
            
            if (manualMappings.length > 0) {
                document.getElementById('manualReviewCard').style.display = 'block';
                document.getElementById('manualMappings').innerHTML = manualMappings.map(m => createMappingCard(m, true)).join('');
            }
        }
        
        function animateValue(id, start, end, duration) {
            const element = document.getElementById(id);
            const range = end - start;
            const increment = range / (duration / 16);
            let current = start;
            
            const timer = setInterval(() => {
                current += increment;
                if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
                    current = end;
                    clearInterval(timer);
                }
                element.textContent = Math.round(current);
            }, 16);
        }
        
        function createMappingCard(m, showDetails = false) {
            const complexityClass = {
                'Simple': 'success',
                'Moderate': 'warning', 
                'Complex': 'danger',
                'ManualRequired': 'secondary'
            }[m.migration_complexity] || 'secondary';
            
            const recommendations = m.recommendations.map(r => `
                <div class="mb-2">
                    <span class="badge bg-primary badge-target me-2">${r.target_type}</span>
                    <span>${r.description}</span>
                    ${r.implementation_notes && showDetails ? `
                        <details class="mt-2">
                            <summary class="text-muted small"><strong>📋 Implementation Steps</strong></summary>
                            <div class="mt-1 small bg-light p-2 rounded" style="white-space: pre-wrap;">${formatNotes(r.implementation_notes)}</div>
                        </details>
                    ` : ''}
                    ${r.kql_query && showDetails ? `
                        <details class="mt-2">
                            <summary class="text-muted small"><strong>📊 KQL Query</strong></summary>
                            <div class="kql-code mt-1"><pre class="mb-0">${escapeHtml(r.kql_query)}</pre></div>
                        </details>
                    ` : ''}
                    ${r.prerequisites && r.prerequisites.length > 0 && showDetails ? `
                        <details class="mt-2">
                            <summary class="text-muted small"><strong>✅ Prerequisites</strong></summary>
                            <ul class="mt-1 small">
                                ${r.prerequisites.map(p => `<li>${escapeHtml(p)}</li>`).join('')}
                            </ul>
                        </details>
                    ` : ''}
                </div>
            `).join('<hr class="my-2">');
            
            const manualSteps = m.manual_steps && m.manual_steps.length > 0 && showDetails ? `
                <div class="mt-3 p-2 bg-warning bg-opacity-10 rounded">
                    <strong class="small"><i class="bi bi-list-check me-1"></i>Migration Steps:</strong>
                    <ol class="small mb-0 mt-1">
                        ${m.manual_steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
                    </ol>
                </div>
            ` : '';
            
            const migrationNotes = m.migration_notes && m.migration_notes.length > 0 && showDetails ? `
                <div class="mt-2 small text-muted">
                    <i class="bi bi-info-circle me-1"></i>
                    ${m.migration_notes.map(n => escapeHtml(n)).join(' | ')}
                </div>
            ` : '';
            
            return `
                <div class="card mapping-card mb-2" data-type="${m.source_type}">
                    <div class="card-body py-2">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <span class="badge bg-info me-2">${m.source_type}</span>
                                <strong>${m.source_name}</strong>
                            </div>
                            <span class="badge bg-${complexityClass}">${m.migration_complexity}</span>
                        </div>
                        <div class="mt-2">
                            ${recommendations}
                        </div>
                        ${manualSteps}
                        ${migrationNotes}
                        ${m.limitations.length > 0 ? `
                            <div class="mt-2">
                                <small class="text-muted">
                                    <i class="bi bi-exclamation-triangle me-1"></i>
                                    ${m.limitations[0]}
                                </small>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }
        
        function formatNotes(text) {
            if (!text) return '';
            var result = escapeHtml(text);
            result = result.split('\\n').join('<br>');
            return result;
        }
        
        function displayMappings(mappings) {
            const mappingsDiv = document.getElementById('mappings');
            
            if (mappings.length === 0) {
                mappingsDiv.innerHTML = '<p class="text-muted">No mappings to display</p>';
                return;
            }
            
            mappingsDiv.innerHTML = mappings.map(m => createMappingCard(m, false)).join('');
        }
        
        function filterMappings(type) {
            document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            if (type === 'all') {
                displayMappings(allMappings);
            } else {
                displayMappings(allMappings.filter(m => m.source_type === type));
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function resetForm() {
            document.getElementById('resultSection').style.display = 'none';
            document.getElementById('uploadSection').style.display = 'block';
            clearFile();
            analysisResult = null;
        }
        
        function downloadArtifact(type) {
            if (!analysisResult) return;
            
            window.location.href = `/api/download/${type}`;
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze an uploaded management pack."""
    global last_analysis
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Please upload .xml or .mp file'}), 400
    
    try:
        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Parse and analyze
        try:
            parser = ManagementPackParser(filepath)
            mp = parser.parse()
        except Exception as parse_error:
            # Clean up on error
            if os.path.exists(filepath):
                os.remove(filepath)
            error_msg = str(parse_error)
            if "XML" in error_msg or "xml" in error_msg or "parse" in error_msg.lower():
                return jsonify({'error': f'Invalid Management Pack XML: The file appears to be corrupted or is not a valid SCOM Management Pack. Please ensure you are uploading a valid .xml or .mp file. Details: {error_msg}'}), 400
            elif "encoding" in error_msg.lower() or "decode" in error_msg.lower():
                return jsonify({'error': 'File encoding error: The file could not be read. Please ensure it is a valid UTF-8 or UTF-16 encoded XML file.'}), 400
            else:
                return jsonify({'error': f'Failed to parse Management Pack: {error_msg}'}), 400
        
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
        
        # Clean up
        os.remove(filepath)
        
        # Return results
        result = report.model_dump()
        result['stats'] = stats
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred while analyzing the Management Pack. Please try again or contact support if the issue persists. Details: {str(e)}'}), 500

@app.route('/api/download/<artifact_type>')
def download(artifact_type):
    """Download generated artifacts."""
    global last_analysis
    
    if not last_analysis:
        return jsonify({'error': 'No analysis available'}), 400
    
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
            return jsonify({'error': 'Invalid artifact type'}), 400
        
        # Create temp file
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(temp_path, 'w') as f:
            f.write(content)
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_server(host='0.0.0.0', port=5000, debug=True):
    """Run the web server."""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║         SCOM to Azure Monitor Migration Tool                  ║
║                     Web Interface                             ║
╚═══════════════════════════════════════════════════════════════╝

Server running at: http://localhost:{port}

Upload your Management Pack files to analyze and generate
Azure Monitor migration artifacts.

Press Ctrl+C to stop the server.
""")
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_server()