"""
SCOM to Azure Monitor Migration Tool - Management Pack Parser

Copyright (c) 2026 Oren Salzberg
Licensed under the MIT License. See LICENSE file in the project root.

Parses SCOM Management Pack (.xml, .mp, or .mpb) files and extracts all relevant
monitoring configurations including monitors, rules, discoveries, and classes.
"""

import re
import zipfile
import tempfile
import os
import io
from pathlib import Path
from typing import Optional, Any
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET

try:
    from cabarchive import CabArchive
    HAS_CABARCHIVE = True
except ImportError:
    HAS_CABARCHIVE = False

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

from .models import (
    ManagementPack,
    ManagementPackMetadata,
    SCOMClass,
    SCOMRelationship,
    SCOMMonitor,
    SCOMRule,
    SCOMDiscovery,
    SCOMDataSource,
    SCOMCondition,
    MonitorType,
    RuleType,
    DataSourceType,
    Severity,
)


class ManagementPackParser:
    """
    Parser for SCOM Management Pack XML files.
    
    Supports sealed (.mp), bundles (.mpb), and unsealed (.xml) management packs.
    """
    
    # Common SCOM XML namespaces
    NAMESPACES = {
        "mp": "http://schemas.microsoft.com/MOMv3/Manifest",
        "xsd": "http://www.w3.org/2001/XMLSchema",
        "mom": "http://schemas.microsoft.com/mom/2005",
        "sc": "http://schemas.microsoft.com/mom/2005/ManagementPack",
        "wsman": "http://schemas.microsoft.com/wbem/wsman/1/config",
    }
    
    # Data source type patterns for identification
    DATA_SOURCE_PATTERNS = {
        DataSourceType.WINDOWS_EVENT: [
            "Microsoft.Windows.EventProvider",
            "EventLog",
            "WindowsEvent",
        ],
        DataSourceType.PERFORMANCE_COUNTER: [
            "Microsoft.Windows.TimedPowerShell.PerformanceProvider",
            "PerformanceCounter",
            "Perf.Counter",
            "System.Performance",
        ],
        DataSourceType.WMI: [
            "Microsoft.Windows.WmiProvider",
            "WMI",
            "WmiQuery",
        ],
        DataSourceType.SCRIPT: [
            "Microsoft.Windows.TimedScript",
            "ScriptProvider",
            "VBScript",
            "JScript",
        ],
        DataSourceType.POWERSHELL: [
            "Microsoft.Windows.TimedPowerShell",
            "PowerShell",
            "PSScript",
        ],
        DataSourceType.LOG_FILE: [
            "Microsoft.Windows.LogFileProvider",
            "LogFile",
            "TextLog",
        ],
        DataSourceType.SNMP: [
            "Microsoft.SystemCenter.Snmp",
            "SNMP",
            "SnmpProbe",
        ],
        DataSourceType.REGISTRY: [
            "Microsoft.Windows.RegistryProvider",
            "Registry",
        ],
        DataSourceType.SERVICE: [
            "Microsoft.Windows.CheckNTServiceState",
            "ServiceMonitor",
            "NTService",
        ],
        DataSourceType.PROCESS: [
            "System.ProcessInformationProvider",
            "Microsoft.Windows.ProcessProvider",
            "ProcessMonitor",
            "ProcessInformation",
        ],
        DataSourceType.HTTP: [
            "Microsoft.SystemCenter.WebApplication",
            "HttpProbe",
            "WebRequest",
        ],
        DataSourceType.DATABASE: [
            "Microsoft.SQLServer",
            "OleDbProbe",
            "Database",
        ],
    }
    
    def __init__(self, file_path: str | Path | None = None, content: bytes | str | None = None):
        """
        Initialize the parser with a management pack file or content.
        
        Args:
            file_path: Path to the management pack XML file
            content: Raw XML content as bytes or string (for serverless environments)
        """
        self.file_path = Path(file_path) if file_path else None
        self._content = content
        self._tree: Optional[ET.ElementTree] = None
        self._root: Optional[ET.Element] = None
        self._detected_namespace: str = ""
        
        if not file_path and not content:
            raise ValueError("Either file_path or content must be provided")
    
    def parse(self) -> ManagementPack:
        """
        Parse the management pack file and return a ManagementPack object.
        
        Returns:
            ManagementPack containing all parsed components
            
        Raises:
            ValueError: If the file is not a valid SCOM Management Pack
        """
        self._load_xml()
        
        # Validate that this is actually a SCOM Management Pack
        self._validate_management_pack()
        
        metadata = self._parse_metadata()
        classes = self._parse_classes()
        relationships = self._parse_relationships()
        monitors = self._parse_monitors()
        rules = self._parse_rules()
        discoveries = self._parse_discoveries()
        
        # Check if we found any components - if not, it's likely not a valid MP
        total_components = len(monitors) + len(rules) + len(discoveries)
        if total_components == 0 and len(classes) == 0:
            raise ValueError(
                "No SCOM components found in the file. This does not appear to be a valid "
                "SCOM Management Pack. Please ensure you are uploading a .xml, .mp, or .mpb file "
                "exported from System Center Operations Manager."
            )
        
        return ManagementPack(
            metadata=metadata,
            classes=classes,
            relationships=relationships,
            monitors=monitors,
            rules=rules,
            discoveries=discoveries,
        )
    
    def _validate_management_pack(self) -> None:
        """
        Validate that the XML is a SCOM Management Pack.
        
        Raises:
            ValueError: If the XML is not a valid SCOM Management Pack
        """
        if self._root is None:
            raise ValueError("Failed to parse XML content")
        
        root_tag = self._root.tag.lower()
        # Remove namespace if present
        if "}" in root_tag:
            root_tag = root_tag.split("}")[1]
        
        # Check for common SCOM MP root elements
        valid_roots = ["managementpack", "manifest", "managementpackfragment", "templategroup"]
        
        if root_tag not in valid_roots:
            # Check if any SCOM-specific elements exist
            has_manifest = self._find(".//Manifest") is not None
            has_monitoring = self._find(".//Monitoring") is not None
            has_type_definitions = self._find(".//TypeDefinitions") is not None
            
            if not (has_manifest or has_monitoring or has_type_definitions):
                raise ValueError(
                    f"This file does not appear to be a SCOM Management Pack. "
                    f"Found root element '{self._root.tag}' but expected a ManagementPack, "
                    f"Manifest, or ManagementPackFragment element. Please upload a valid "
                    f"SCOM Management Pack XML file."
                )

    def _load_xml(self) -> None:
        """Load and parse the XML file or content safely. Handles both .xml and .mp (CAB) files."""
        xml_content = None
        
        if self._content:
            # Check if content is a sealed MP (CAB/ZIP archive)
            content_bytes = self._content if isinstance(self._content, bytes) else self._content.encode('utf-8')
            xml_content = self._extract_xml_from_content(content_bytes)
            
            if xml_content:
                self._root = SafeET.fromstring(xml_content)
            else:
                # Parse as raw XML
                if isinstance(self._content, str):
                    self._root = SafeET.fromstring(self._content)
                else:
                    self._root = SafeET.fromstring(self._content)
            self._tree = ET.ElementTree(self._root)
        elif self.file_path:
            if not self.file_path.exists():
                raise FileNotFoundError(f"Management pack not found: {self.file_path}")
            
            # Check if it's a .mp or .mpb file (sealed management pack / bundle - CAB archive)
            if self.file_path.suffix.lower() in ['.mp', '.mpb']:
                xml_content = self._extract_xml_from_mp_file(self.file_path)
                if xml_content:
                    self._root = SafeET.fromstring(xml_content)
                    self._tree = ET.ElementTree(self._root)
                else:
                    raise ValueError(
                        "Could not extract XML from sealed management pack (.mp/.mpb file). "
                        "The file may be corrupted or in an unsupported format. "
                        "Try exporting the unsealed XML version from SCOM."
                    )
            else:
                # Use defusedxml for safe parsing of regular XML files
                self._tree = SafeET.parse(str(self.file_path))
                self._root = self._tree.getroot()
        else:
            raise ValueError("No file path or content provided")
        
        # Detect namespace from root element
        if self._root.tag.startswith("{"):
            self._detected_namespace = self._root.tag.split("}")[0] + "}"
    
    def _extract_xml_from_content(self, content: bytes) -> Optional[str]:
        """
        Try to extract XML from content that may be a sealed MP (CAB/ZIP archive).
        
        Args:
            content: Raw bytes that may be a CAB/ZIP archive or raw XML
            
        Returns:
            Extracted XML string if content was an archive, None if raw XML
        """
        import logging
        logging.info(f'Checking content type, first 10 bytes: {content[:10]}')
        
        # Check for OLE Compound Document (MPB bundles use this format)
        # Magic bytes: D0 CF 11 E0 A1 B1 1A E1
        is_ole = content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        if is_ole:
            logging.info('File appears to be an OLE Compound Document (MPB bundle)')
            xml_content = self._extract_xml_from_ole(content)
            if xml_content:
                return xml_content
        
        # Check for ZIP/CAB magic bytes
        # ZIP: PK (0x50 0x4B)
        # CAB: MSCF (0x4D 0x53 0x43 0x46)
        is_zip = content[:2] == b'PK'
        is_cab = content[:4] == b'MSCF'
        
        logging.info(f'Is ZIP: {is_zip}, Is CAB: {is_cab}')
        
        # Check for PE/DLL (sealed .mp files are .NET assemblies)
        is_pe = content[:2] == b'MZ'
        if is_pe:
            logging.info('File appears to be a sealed .NET assembly (PE/DLL)')
            # Sealed management packs are compiled .NET assemblies
            # The XML is embedded as a .NET resource and requires the .NET runtime to extract
            # Try our best-effort extraction
            xml_content = self._extract_xml_from_assembly(content)
            if xml_content:
                return xml_content
            else:
                # Cannot extract from sealed MP - provide clear guidance
                raise ValueError(
                    "This appears to be a sealed Management Pack (.mp file). "
                    "Sealed MPs are compiled .NET assemblies that require special tools to extract. "
                    "\\n\\nTo analyze this MP, please export the unsealed XML version from SCOM:\\n"
                    "1. Open SCOM Console\\n"
                    "2. Go to Administration > Management Packs\\n"
                    "3. Right-click the MP and select 'Export Management Pack'\\n"
                    "4. Save as .xml file and upload that instead\\n\\n"
                    "Alternatively, look for an .xml version of this MP in the Management Pack catalog."
                )
        
        if is_zip or is_cab:
            # Try as ZIP first (some .mp files are ZIP format)
            if is_zip:
                try:
                    with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                        logging.info(f'ZIP file contains: {zf.namelist()}')
                        for name in zf.namelist():
                            if name.lower().endswith('.xml'):
                                return zf.read(name).decode('utf-8')
                        # If no .xml file, try the first file
                        if zf.namelist():
                            return zf.read(zf.namelist()[0]).decode('utf-8')
                except zipfile.BadZipFile as e:
                    logging.info(f'Not a valid ZIP file: {e}')
            
            # Try CAB extraction
            xml_content = self._extract_from_cab_bytes(content)
            if xml_content:
                logging.info('Successfully extracted XML from CAB')
                return xml_content
            else:
                logging.info('CAB extraction returned None')
        
        # Not an archive, check if it starts with XML marker
        if content.strip()[:5] in [b'<?xml', b'<Mani', b'<mani']:
            logging.info('Content appears to be raw XML')
            return None  # Return None to indicate it should be parsed as raw XML
            
        # Try CAB extraction anyway (some files don't have proper magic bytes)
        logging.info('Trying CAB extraction as fallback...')
        xml_content = self._extract_from_cab_bytes(content)
        if xml_content:
            logging.info('Fallback CAB extraction succeeded')
            return xml_content
        
        logging.info('Could not extract as archive, treating as raw XML')
        return None
    
    def _extract_xml_from_assembly(self, content: bytes) -> Optional[str]:
        """
        Extract XML manifest from a sealed SCOM management pack (.NET assembly).
        
        Sealed .mp files are .NET assemblies with embedded XML manifests.
        The XML is typically stored as a resource or can be found by searching
        for XML patterns in the binary.
        
        Args:
            content: Raw bytes of the .NET assembly
            
        Returns:
            Extracted XML string or None
        """
        import logging
        import re
        
        # Method 1: Search for XML manifest pattern in binary
        # SCOM MPs typically have XML starting with <?xml or <ManagementPack
        xml_patterns = [
            b'<\\?xml[^>]*>\\s*<ManagementPack',
            b'<ManagementPack[^>]*xmlns',
            b'<\\?xml[^>]*>\\s*<Manifest',
        ]
        
        for pattern in xml_patterns:
            match = re.search(pattern, content)
            if match:
                start_pos = match.start()
                logging.info(f'Found XML pattern at position {start_pos}')
                
                # Find the end of the XML (look for closing tag)
                # Try to find </ManagementPack> or </Manifest>
                end_patterns = [b'</ManagementPack>', b'</Manifest>']
                end_pos = -1
                for end_pattern in end_patterns:
                    pos = content.rfind(end_pattern)
                    if pos > start_pos:
                        end_pos = pos + len(end_pattern)
                        break
                
                if end_pos > start_pos:
                    try:
                        xml_bytes = content[start_pos:end_pos]
                        # Try to decode - handle BOM and different encodings
                        for encoding in ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'latin-1']:
                            try:
                                xml_str = xml_bytes.decode(encoding)
                                # Validate it's actually XML
                                if '<ManagementPack' in xml_str or '<Manifest' in xml_str:
                                    logging.info(f'Successfully extracted XML using {encoding} encoding')
                                    return xml_str
                            except (UnicodeDecodeError, UnicodeError):
                                continue
                    except Exception as e:
                        logging.error(f'Error extracting XML: {e}')
        
        # Method 2: Look for UTF-16 encoded XML (common in .NET resources)
        # Search for UTF-16 LE BOM followed by XML declaration
        utf16_pattern = b'<\x00\\?\x00x\x00m\x00l\x00'
        match = re.search(utf16_pattern, content)
        if match:
            start_pos = match.start()
            logging.info(f'Found UTF-16 XML at position {start_pos}')
            # Find end
            end_marker = b'<\x00/\x00M\x00a\x00n\x00a\x00g\x00e\x00m\x00e\x00n\x00t\x00P\x00a\x00c\x00k\x00>\x00'
            end_pos = content.find(end_marker, start_pos)
            if end_pos > 0:
                end_pos += len(end_marker)
                try:
                    xml_str = content[start_pos:end_pos].decode('utf-16-le')
                    if '<ManagementPack' in xml_str:
                        logging.info('Successfully extracted UTF-16 XML')
                        return xml_str
                except:
                    pass
        
        logging.info('Could not extract XML from assembly')
        return None
    
    def _extract_xml_from_ole(self, content: bytes) -> Optional[str]:
        """
        Extract XML manifest from an OLE Compound Document (.mpb bundle).
        
        MPB (Management Pack Bundle) files are OLE Compound Documents that
        contain multiple management packs. The XML manifests are stored
        in streams within the OLE structure.
        
        Args:
            content: Raw bytes of the OLE Compound Document
            
        Returns:
            Extracted XML string or None
        """
        import logging
        
        if not HAS_OLEFILE:
            logging.warning('olefile library not available, cannot extract from OLE document')
            raise ValueError(
                "This appears to be a Management Pack Bundle (.mpb file). "
                "The olefile library is required to extract content from MPB bundles. "
                "Please install it with: pip install olefile\\n\\n"
                "Alternatively, extract the individual MPs from the bundle using SCOM:\\n"
                "1. Import the MPB into SCOM\\n"
                "2. Export each MP individually as XML"
            )
        
        try:
            import io
            ole = olefile.OleFileIO(io.BytesIO(content))
            
            logging.info(f'OLE file opened, root entries: {ole.listdir()}')
            
            xml_contents = []
            
            # Iterate through all streams in the OLE file
            for entry in ole.listdir():
                stream_name = '/'.join(entry)
                logging.info(f'Found OLE stream: {stream_name}')
                
                try:
                    stream_data = ole.openstream(entry).read()
                    
                    # Check if this stream contains XML
                    # Look for common XML markers
                    if (stream_data.strip()[:5] in [b'<?xml', b'<Mani', b'<mani'] or
                        b'<ManagementPack' in stream_data[:1000] or
                        b'<Manifest' in stream_data[:1000]):
                        
                        # Try to decode the XML
                        for encoding in ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'latin-1']:
                            try:
                                xml_str = stream_data.decode(encoding)
                                if '<ManagementPack' in xml_str or '<Manifest' in xml_str:
                                    logging.info(f'Found XML in stream: {stream_name} ({encoding})')
                                    xml_contents.append(xml_str)
                                    break
                            except (UnicodeDecodeError, UnicodeError):
                                continue
                    
                    # Also check for compressed/nested CAB files within the OLE
                    elif stream_data[:4] == b'MSCF':
                        logging.info(f'Found embedded CAB in stream: {stream_name}')
                        nested_xml = self._extract_from_cab_bytes(stream_data)
                        if nested_xml:
                            xml_contents.append(nested_xml)
                        else:
                            # CAB extraction failed - likely LZX compression without cabextract
                            logging.warning(f'Failed to extract CAB from OLE stream: {stream_name}')
                    
                    # Check for nested OLE
                    elif stream_data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                        logging.info(f'Found nested OLE in stream: {stream_name}')
                        nested_xml = self._extract_xml_from_ole(stream_data)
                        if nested_xml:
                            xml_contents.append(nested_xml)
                            
                except Exception as e:
                    logging.debug(f'Error reading stream {stream_name}: {e}')
                    continue
            
            ole.close()
            
            if xml_contents:
                # If we found multiple XMLs, return the first one for now
                # (could be enhanced to merge or handle multiple MPs)
                logging.info(f'Extracted {len(xml_contents)} XML document(s) from OLE')
                return xml_contents[0]
            
            logging.info('No XML content found in OLE streams')
            # Provide a helpful error message for MPB files that couldn't be extracted
            raise ValueError(
                "This Management Pack Bundle (.mpb) file uses LZX compression which requires "
                "the 'cabextract' system utility to extract.\\n\\n"
                "Please export the MP as XML from SCOM Console instead:\\n"
                "1. Import the MPB into SCOM if not already done\\n"
                "2. Go to Administration > Management Packs\\n"
                "3. Right-click the MP and select 'Export Management Pack'\\n"
                "4. Save as .xml file and upload that instead"
            )
            
        except Exception as e:
            logging.error(f'Error parsing OLE file: {e}')
            raise ValueError(
                f"Failed to extract content from this Management Pack Bundle (.mpb file). "
                f"Error: {str(e)}\\n\\n"
                "Please try exporting the MP as XML from SCOM Console instead."
            )
    
    def _extract_xml_from_mp_file(self, file_path: Path) -> Optional[str]:
        """
        Extract XML content from a sealed management pack (.mp) file.
        
        Sealed MPs are CAB archives containing the XML manifest.
        
        Args:
            file_path: Path to the .mp file
            
        Returns:
            Extracted XML content as string, or None if extraction failed
        """
        # Read the file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Try extraction from content
        xml_content = self._extract_xml_from_content(content)
        if xml_content:
            return xml_content
        
        # Try using system cabextract command (Linux/Mac)
        try:
            import subprocess
            with tempfile.TemporaryDirectory() as tmpdir:
                result = subprocess.run(
                    ['cabextract', '-d', tmpdir, str(file_path)],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    # Find extracted XML file
                    for fname in os.listdir(tmpdir):
                        if fname.lower().endswith('.xml'):
                            xml_path = os.path.join(tmpdir, fname)
                            with open(xml_path, 'r', encoding='utf-8') as f:
                                return f.read()
                    # Try first file if no .xml found
                    files = os.listdir(tmpdir)
                    if files:
                        with open(os.path.join(tmpdir, files[0]), 'r', encoding='utf-8') as f:
                            return f.read()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
        
        # Try using Python's zipfile (some MPs are actually ZIP format)
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                for name in zf.namelist():
                    if name.lower().endswith('.xml'):
                        return zf.read(name).decode('utf-8')
                # If no .xml, try first file
                if zf.namelist():
                    return zf.read(zf.namelist()[0]).decode('utf-8')
        except zipfile.BadZipFile:
            pass
        
        return None
    
    def _extract_from_cab_bytes(self, content: bytes) -> Optional[str]:
        """
        Extract XML from CAB archive bytes.
        
        Args:
            content: CAB file content as bytes
            
        Returns:
            Extracted XML string or None
        """
        import logging
        
        # Try using cabarchive library first (pure Python, works everywhere)
        logging.info(f'HAS_CABARCHIVE: {HAS_CABARCHIVE}')
        if HAS_CABARCHIVE:
            try:
                logging.info('Attempting to parse with cabarchive library...')
                cab = CabArchive(content)
                files_in_cab = []
                for cf in cab:
                    files_in_cab.append(cf.filename)
                    # Look for XML file in the archive
                    if cf.filename.lower().endswith('.xml'):
                        logging.info(f'Found XML file in CAB: {cf.filename}')
                        return cf.buf.decode('utf-8')
                logging.info(f'Files in CAB: {files_in_cab}')
                # If no .xml file found, try the first file
                for cf in cab:
                    try:
                        content_str = cf.buf.decode('utf-8')
                        # Check if it looks like XML
                        if content_str.strip().startswith('<?xml') or content_str.strip().startswith('<'):
                            logging.info(f'Using non-.xml file that contains XML: {cf.filename}')
                            return content_str
                    except UnicodeDecodeError:
                        continue
            except Exception as e:
                logging.error(f'cabarchive extraction failed: {e}')
        
        # Fallback: try using subprocess cabextract (Linux/Mac)
        try:
            import subprocess
            logging.info('Trying subprocess cabextract...')
            with tempfile.TemporaryDirectory() as tmpdir:
                # Write content to temp file
                cab_path = os.path.join(tmpdir, 'temp.mp')
                with open(cab_path, 'wb') as f:
                    f.write(content)
                
                # Try cabextract
                result = subprocess.run(
                    ['cabextract', '-d', tmpdir, cab_path],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    for fname in os.listdir(tmpdir):
                        if fname.lower().endswith('.xml'):
                            xml_path = os.path.join(tmpdir, fname)
                            with open(xml_path, 'r', encoding='utf-8') as f:
                                return f.read()
        except (subprocess.SubprocessError, FileNotFoundError, OSError, NameError):
            pass
        
        return None
        
    def _find(self, path: str, element: Optional[ET.Element] = None) -> Optional[ET.Element]:
        """Find element with namespace handling."""
        root = element if element is not None else self._root
        
        # Try with namespace first
        if self._detected_namespace:
            ns_path = "/".join(
                f"{self._detected_namespace}{p}" if p and not p.startswith("@") else p
                for p in path.split("/")
            )
            result = root.find(ns_path)
            if result is not None:
                return result
        
        # Try without namespace
        result = root.find(path)
        if result is not None:
            return result
            
        # Try with common namespace prefixes
        for prefix, uri in self.NAMESPACES.items():
            ns_path = path
            for part in path.split("/"):
                if part and not part.startswith("@") and not part.startswith("{"):
                    ns_path = ns_path.replace(part, f"{{{uri}}}{part}", 1)
            result = root.find(ns_path)
            if result is not None:
                return result
        
        return None
    
    def _findall(self, path: str, element: Optional[ET.Element] = None) -> list[ET.Element]:
        """Find all elements with namespace handling."""
        root = element if element is not None else self._root
        results = []
        
        # Try with detected namespace
        if self._detected_namespace:
            ns_path = "/".join(
                f"{self._detected_namespace}{p}" if p and not p.startswith("@") else p
                for p in path.split("/")
            )
            results = root.findall(ns_path)
            if results:
                return results
        
        # Try without namespace
        results = root.findall(path)
        if results:
            return results
        
        # Use iter to find all matching elements by local name
        target_name = path.split("/")[-1]
        results = [
            elem for elem in root.iter()
            if elem.tag.endswith(target_name) or elem.tag == target_name
        ]
        
        return results
    
    def _get_text(self, element: Optional[ET.Element], default: str = "") -> str:
        """Safely get element text."""
        if element is None:
            return default
        return element.text.strip() if element.text else default
    
    def _get_attr(self, element: Optional[ET.Element], attr: str, default: str = "") -> str:
        """Safely get element attribute."""
        if element is None:
            return default
        return element.get(attr, default)
    
    def _parse_metadata(self) -> ManagementPackMetadata:
        """Parse management pack identity and metadata."""
        # Try different paths for manifest/identity
        identity = self._find(".//Identity") or self._find(".//Manifest/Identity")
        
        mp_id = ""
        version = ""
        
        if identity is not None:
            mp_id = self._get_attr(identity, "ID") or self._get_text(
                self._find("ID", identity)
            )
            version = self._get_attr(identity, "Version") or self._get_text(
                self._find("Version", identity)
            )
        
        # Try to get ID from root if not found
        if not mp_id and self._root is not None:
            mp_id = self._get_attr(self._root, "ID", "")
        
        # Get display strings
        display_name = ""
        description = ""
        
        display_strings = self._findall(".//DisplayString")
        for ds in display_strings:
            element_id = self._get_attr(ds, "ElementID")
            if element_id == mp_id or not display_name:
                name_elem = self._find("Name", ds)
                desc_elem = self._find("Description", ds)
                if name_elem is not None:
                    display_name = self._get_text(name_elem)
                if desc_elem is not None:
                    description = self._get_text(desc_elem)
        
        # Parse references
        references = []
        ref_elements = self._findall(".//Reference")
        for ref in ref_elements:
            ref_id = self._get_attr(ref, "Alias") or self._get_text(self._find("ID", ref))
            if ref_id:
                references.append(ref_id)
        
        # Get fallback name from file path or use default
        fallback_name = self.file_path.stem if self.file_path else "UnknownManagementPack"
        
        return ManagementPackMetadata(
            id=mp_id or fallback_name,
            name=mp_id or fallback_name,
            version=version or "1.0.0",
            display_name=display_name or mp_id or fallback_name,
            description=description,
            references=references,
        )
    
    def _parse_classes(self) -> list[SCOMClass]:
        """Parse class type definitions."""
        classes = []
        
        # Find all class definitions
        class_elements = self._findall(".//ClassType") + self._findall(".//ClassTypes/ClassType")
        
        for elem in class_elements:
            class_id = self._get_attr(elem, "ID")
            if not class_id:
                continue
            
            # Parse properties
            properties = {}
            for prop in self._findall(".//Property", elem):
                prop_id = self._get_attr(prop, "ID")
                prop_type = self._get_attr(prop, "Type", "string")
                if prop_id:
                    properties[prop_id] = prop_type
            
            classes.append(SCOMClass(
                id=class_id,
                name=class_id,
                base_class=self._get_attr(elem, "Base", ""),
                is_abstract=self._get_attr(elem, "Abstract", "false").lower() == "true",
                is_singleton=self._get_attr(elem, "Singleton", "false").lower() == "true",
                properties=properties,
            ))
        
        return classes
    
    def _parse_relationships(self) -> list[SCOMRelationship]:
        """Parse relationship type definitions."""
        relationships = []
        
        rel_elements = self._findall(".//RelationshipType") + self._findall(".//RelationshipTypes/RelationshipType")
        
        for elem in rel_elements:
            rel_id = self._get_attr(elem, "ID")
            if not rel_id:
                continue
            
            source = self._find("Source", elem)
            target = self._find("Target", elem)
            
            relationships.append(SCOMRelationship(
                id=rel_id,
                name=rel_id,
                source_class=self._get_attr(source, "ID", "") if source is not None else "",
                target_class=self._get_attr(target, "ID", "") if target is not None else "",
                relationship_type=self._get_attr(elem, "Base", "Hosting"),
            ))
        
        return relationships
    
    def _parse_monitors(self) -> list[SCOMMonitor]:
        """Parse all monitor definitions."""
        monitors = []
        
        # Find unit monitors
        monitor_elements = (
            self._findall(".//UnitMonitor") +
            self._findall(".//AggregateMonitor") +
            self._findall(".//DependencyMonitor") +
            self._findall(".//Monitors/UnitMonitor")
        )
        
        for elem in monitor_elements:
            monitor = self._parse_single_monitor(elem)
            if monitor:
                monitors.append(monitor)
        
        return monitors
    
    def _parse_single_monitor(self, elem: ET.Element) -> Optional[SCOMMonitor]:
        """Parse a single monitor element."""
        monitor_id = self._get_attr(elem, "ID")
        if not monitor_id:
            return None
        
        # Determine monitor type from element tag
        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        monitor_type = MonitorType.UNIT_MONITOR
        if "Aggregate" in tag_name:
            monitor_type = MonitorType.AGGREGATE_MONITOR
        elif "Dependency" in tag_name:
            monitor_type = MonitorType.DEPENDENCY_MONITOR
        
        # Get target class
        target = self._get_attr(elem, "Target")
        
        # Parse configuration
        config = self._find(".//Configuration", elem)
        data_source = self._parse_data_source(elem)
        
        # Parse alert settings
        alert_settings = self._find(".//AlertSettings", elem)
        generates_alert = alert_settings is not None
        alert_severity = Severity.WARNING
        alert_message = ""
        
        if alert_settings is not None:
            severity_elem = self._find("AlertSeverity", alert_settings)
            if severity_elem is not None:
                sev_text = self._get_text(severity_elem).lower()
                if "error" in sev_text or "critical" in sev_text:
                    alert_severity = Severity.CRITICAL
                elif "info" in sev_text:
                    alert_severity = Severity.INFORMATION
            
            message_elem = self._find(".//AlertMessage", alert_settings)
            if message_elem is not None:
                alert_message = self._get_attr(message_elem, "ResourceID") or self._get_text(message_elem)
        
        # Parse thresholds from configuration - more comprehensive extraction
        threshold = None
        threshold_operator = None
        if config is not None:
            # Try multiple threshold element names
            threshold_elem = (
                self._find(".//Threshold", config) or
                self._find(".//ThresholdValue", config) or
                self._find(".//Value", config)
            )
            if threshold_elem is not None:
                try:
                    threshold = float(self._get_text(threshold_elem))
                except ValueError:
                    pass
            
            # For process monitors, look for MinProcessCount and MaxProcessCount
            if not threshold:
                min_count = self._find(".//MinProcessCount", config)
                max_count = self._find(".//MaxProcessCount", config)
                if min_count is not None:
                    try:
                        threshold = float(self._get_text(min_count))
                        threshold_operator = "GreaterEqual"
                    except ValueError:
                        pass
                elif max_count is not None:
                    try:
                        threshold = float(self._get_text(max_count))
                        threshold_operator = "LessEqual"
                    except ValueError:
                        pass
            
            # Look for direction/operator patterns
            if not threshold_operator:
                direction_elem = self._find(".//Direction", config)
                if direction_elem is not None:
                    direction = self._get_text(direction_elem).lower()
                    if "over" in direction or "greater" in direction:
                        threshold_operator = "GreaterThan"
                    elif "under" in direction or "less" in direction:
                        threshold_operator = "LessThan"
                    elif "equal" in direction:
                        threshold_operator = "Equals"
            
            # Look for explicit operator patterns
            if not threshold_operator:
                for pattern in ["GreaterThan", "LessThan", "Equals", "GreaterThanOrEqual", "LessThanOrEqual"]:
                    if self._find(f".//{pattern}", config) is not None:
                        threshold_operator = pattern
                        break
            
            # Check operator attributes
            if not threshold_operator:
                operator_attr = self._get_attr(config, "Operator")
                if operator_attr:
                    threshold_operator = operator_attr
        
        # Get display name from display strings
        display_name = self._get_display_string(monitor_id)
        
        return SCOMMonitor(
            id=monitor_id,
            name=monitor_id,
            display_name=display_name,
            target_class=target,
            monitor_type=monitor_type,
            monitor_type_id=self._get_attr(elem, "TypeID"),
            parent_monitor_id=self._get_attr(elem, "ParentMonitorID"),
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            generates_alert=generates_alert,
            alert_severity=alert_severity,
            alert_message=alert_message,
            threshold=threshold,
            threshold_operator=threshold_operator,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_rules(self) -> list[SCOMRule]:
        """Parse all rule definitions."""
        rules = []
        
        rule_elements = self._findall(".//Rule") + self._findall(".//Rules/Rule")
        
        for elem in rule_elements:
            rule = self._parse_single_rule(elem)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_single_rule(self, elem: ET.Element) -> Optional[SCOMRule]:
        """Parse a single rule element."""
        rule_id = self._get_attr(elem, "ID")
        if not rule_id:
            return None
        
        target = self._get_attr(elem, "Target")
        data_source = self._parse_data_source(elem)
        
        # Determine rule type based on content
        rule_type = self._determine_rule_type(elem, data_source)
        
        # Check for alert generation
        write_actions = self._findall(".//WriteAction", elem)
        generates_alert = any(
            "Alert" in self._get_attr(wa, "ID", "") or "Alert" in self._get_attr(wa, "TypeID", "")
            for wa in write_actions
        )
        
        # Parse alert settings if present
        alert_severity = Severity.WARNING
        alert_message = ""
        for wa in write_actions:
            if "Alert" in self._get_attr(wa, "ID", "") or "Alert" in self._get_attr(wa, "TypeID", ""):
                severity_elem = self._find(".//Severity", wa) or self._find(".//Priority", wa)
                if severity_elem is not None:
                    sev_text = self._get_text(severity_elem)
                    if sev_text in ["1", "2"] or "critical" in sev_text.lower():
                        alert_severity = Severity.CRITICAL
                    elif sev_text == "0" or "info" in sev_text.lower():
                        alert_severity = Severity.INFORMATION
        
        display_name = self._get_display_string(rule_id)
        
        return SCOMRule(
            id=rule_id,
            name=rule_id,
            display_name=display_name,
            target_class=target,
            rule_type=rule_type,
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            generates_alert=generates_alert,
            alert_severity=alert_severity,
            alert_message=alert_message,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_discoveries(self) -> list[SCOMDiscovery]:
        """Parse all discovery definitions."""
        discoveries = []
        
        # Use set to avoid duplicates - Discovery elements may be found in multiple paths
        discovery_ids_seen = set()
        discovery_elements = []
        for elem in self._findall(".//Discovery"):
            elem_id = elem.get("ID")
            if elem_id and elem_id not in discovery_ids_seen:
                discovery_ids_seen.add(elem_id)
                discovery_elements.append(elem)
        
        for elem in discovery_elements:
            discovery = self._parse_single_discovery(elem)
            if discovery:
                discoveries.append(discovery)
        
        return discoveries
    
    def _parse_single_discovery(self, elem: ET.Element) -> Optional[SCOMDiscovery]:
        """Parse a single discovery element."""
        discovery_id = self._get_attr(elem, "ID")
        if not discovery_id:
            return None
        
        target = self._get_attr(elem, "Target")
        data_source = self._parse_data_source(elem)
        
        # Get discovered types
        discovered_class = ""
        discovery_types = self._findall(".//DiscoveryType", elem)
        if discovery_types:
            for dt in discovery_types:
                class_elem = self._find(".//ClassType", dt)
                if class_elem is not None:
                    discovered_class = self._get_attr(class_elem, "TypeID", "")
                    break
        
        display_name = self._get_display_string(discovery_id)
        
        return SCOMDiscovery(
            id=discovery_id,
            name=discovery_id,
            display_name=display_name,
            target_class=target,
            discovered_class=discovered_class,
            enabled=self._get_attr(elem, "Enabled", "true").lower() != "false",
            data_source=data_source,
            raw_xml=ET.tostring(elem, encoding="unicode"),
        )
    
    def _parse_data_source(self, parent: ET.Element) -> Optional[SCOMDataSource]:
        """Parse data source configuration from a parent element."""
        # Look for data source elements
        ds_elem = (
            self._find(".//DataSource", parent) or
            self._find(".//DataSources/DataSource", parent) or
            self._find(".//ProbeAction", parent)
        )
        
        # Also check Configuration element for inline configurations (like service monitors)
        config_elem = self._find(".//Configuration", parent)
        
        if ds_elem is None and config_elem is None:
            return None
        
        # Use config_elem if ds_elem is not found (common for unit monitors)
        source_elem = ds_elem if ds_elem is not None else config_elem
        
        ds_id = self._get_attr(source_elem, "ID", "DataSource")
        type_id = self._get_attr(parent, "TypeID", "") or self._get_attr(source_elem, "TypeID", "")
        
        # Determine data source type
        ds_type = self._identify_data_source_type(type_id, source_elem)
        
        # Parse interval
        interval = None
        interval_elem = self._find(".//IntervalSeconds", source_elem) or self._find(".//Frequency", source_elem)
        if interval_elem is not None:
            try:
                interval = int(self._get_text(interval_elem))
            except ValueError:
                pass
        
        # Parse type-specific fields
        data_source = SCOMDataSource(
            id=ds_id,
            type_id=type_id,
            data_source_type=ds_type,
            interval_seconds=interval,
        )
        
        # Windows Event specific
        log_name = self._find(".//LogName", source_elem)
        if log_name is not None:
            data_source.event_log = self._get_text(log_name)
        
        event_id = self._find(".//EventDisplayNumber", source_elem) or self._find(".//EventID", source_elem)
        if event_id is not None:
            try:
                data_source.event_id = int(self._get_text(event_id))
            except ValueError:
                pass
        
        # Event source
        event_source = self._find(".//PublisherName", source_elem) or self._find(".//Source", source_elem)
        if event_source is not None:
            data_source.event_source = self._get_text(event_source)
        
        # Performance counter specific
        for field, names in [
            ("performance_object", ["ObjectName", "Object", "CounterObject"]),
            ("performance_counter", ["CounterName", "Counter"]),
            ("performance_instance", ["InstanceName", "Instance"]),
        ]:
            for name in names:
                elem = self._find(f".//{name}", source_elem)
                if elem is not None:
                    setattr(data_source, field, self._get_text(elem))
                    break
        
        # WMI specific
        wmi_ns = self._find(".//Namespace", source_elem) or self._find(".//NameSpace", source_elem)
        if wmi_ns is not None:
            data_source.wmi_namespace = self._get_text(wmi_ns)
        
        wmi_query = self._find(".//Query", source_elem)
        if wmi_query is not None:
            data_source.wmi_query = self._get_text(wmi_query)
        
        # Script specific
        script_name = self._find(".//ScriptName", source_elem)
        if script_name is not None:
            data_source.script_name = self._get_text(script_name)
        
        script_body = self._find(".//ScriptBody", source_elem)
        if script_body is not None:
            data_source.script_body = self._get_text(script_body)
        
        # Service monitor specific - ENHANCED
        service_name = self._find(".//ServiceName", source_elem)
        if service_name is not None:
            data_source.service_name = self._get_text(service_name)
            # If we found a service name, ensure this is classified as a service monitor
            if ds_type == DataSourceType.UNKNOWN:
                data_source.data_source_type = DataSourceType.SERVICE
        
        # Process monitor specific - extract process name from Configuration
        process_name = self._find(".//ProcessName", source_elem)
        if process_name is not None:
            process_name_text = self._get_text(process_name)
            if process_name_text:
                # Store process name in service_name field for now (models.py uses this field)
                data_source.service_name = process_name_text
                # If we found a process name, ensure this is classified as a process monitor
                if ds_type == DataSourceType.UNKNOWN:
                    data_source.data_source_type = DataSourceType.PROCESS
        
        return data_source
    
    def _identify_data_source_type(self, type_id: str, elem: ET.Element) -> DataSourceType:
        """Identify the type of data source from its type ID and content."""
        type_id_lower = type_id.lower()
        elem_str = ET.tostring(elem, encoding="unicode").lower()
        
        for ds_type, patterns in self.DATA_SOURCE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in type_id_lower or pattern.lower() in elem_str:
                    return ds_type
        
        return DataSourceType.UNKNOWN
    
    def _determine_rule_type(self, elem: ET.Element, data_source: Optional[SCOMDataSource]) -> RuleType:
        """Determine the type of rule based on its configuration."""
        elem_str = ET.tostring(elem, encoding="unicode").lower()
        
        if "alert" in elem_str:
            return RuleType.ALERT_RULE
        
        if data_source:
            if data_source.data_source_type == DataSourceType.WINDOWS_EVENT:
                return RuleType.EVENT_RULE
            elif data_source.data_source_type == DataSourceType.PERFORMANCE_COUNTER:
                return RuleType.PERFORMANCE_RULE
            elif data_source.data_source_type in [DataSourceType.SCRIPT, DataSourceType.POWERSHELL]:
                return RuleType.SCRIPT_RULE
        
        # Check write actions for collection
        write_actions = self._findall(".//WriteAction", elem)
        for wa in write_actions:
            wa_type = self._get_attr(wa, "TypeID", "").lower()
            if "performance" in wa_type or "collect" in wa_type:
                return RuleType.COLLECTION_RULE
        
        return RuleType.COLLECTION_RULE
    
    def _get_display_string(self, element_id: str) -> str:
        """Get display string for an element ID."""
        display_strings = self._findall(".//DisplayString")
        for ds in display_strings:
            if self._get_attr(ds, "ElementID") == element_id:
                name_elem = self._find("Name", ds)
                if name_elem is not None:
                    return self._get_text(name_elem)
        return element_id
    
    @staticmethod
    def is_management_pack(file_path: str | Path) -> bool:
        """Check if a file appears to be a SCOM management pack."""
        path = Path(file_path)
        if not path.exists():
            return False
        
        if path.suffix.lower() not in [".xml", ".mp", ".mpb"]:
            return False
        
        try:
            # Quick check for MP markers
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)  # Read first 5KB
                markers = [
                    "ManagementPack",
                    "MOMv3",
                    "<Manifest>",
                    "<TypeDefinitions>",
                    "<Monitoring>",
                ]
                return any(marker in content for marker in markers)
        except Exception:
            return False
