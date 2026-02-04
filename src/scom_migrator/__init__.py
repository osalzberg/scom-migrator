"""
SCOM to Azure Monitor Migration Tool

This package provides tools to migrate SCOM Management Packs to Azure Monitor.
"""

__version__ = "1.1.0"
__author__ = "SCOM Migrator Team"

from .parser import ManagementPackParser
from .analyzer import MigrationAnalyzer
from .mapper import AzureMonitorMapper
from .generator import ARMTemplateGenerator

__all__ = [
    "ManagementPackParser",
    "MigrationAnalyzer", 
    "AzureMonitorMapper",
    "ARMTemplateGenerator",
]
