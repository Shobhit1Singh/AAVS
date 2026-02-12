"""
API Parser Module
Parses OpenAPI/Swagger specifications and extracts endpoint information
for security testing and fuzzing.
"""

import prance
import yaml
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APIParser:
    """
    Parses OpenAPI/Swagger specification files and extracts information
    needed for API security testing.
    """
    
    def __init__(self, spec_path: str):
        """
        Initialize the API parser.
        
        Args:
            spec_path (str): Path to OpenAPI specification file (.yaml or .json)
        
        Raises:
            FileNotFoundError: If spec file doesn't exist
            ValueError: If spec file is invalid
        """
        self.spec_path = Path(spec_path)
        self.spec = None
        self.base_url = None
        self.endpoints = []
        
        # Validate file exists
        if not self.spec_path.exists():
            raise FileNotFoundError(f"Spec file not found: {spec_path}")
        
        # Parse the specification
        self._parse_spec()
        
        logger.info(f"{Fore.GREEN}Successfully parsed API spec: {self.spec_path.name}")
    
    def _parse_spec(self):
        """
        Parse the OpenAPI specification file.
        Resolves all $ref references automatically.
        """
        try:
            # Use prance to parse and resolve references
            parser = prance.ResolvingParser(str(self.spec_path))
            self.spec = parser.specification
            
            # Extract basic info
            self._extract_base_info()
            
        except Exception as e:
            logger.error(f"{Fore.RED}Failed to parse spec: {e}")
            raise ValueError(f"Invalid OpenAPI specification: {e}")
    
    def _extract_base_info(self):
        """Extract basic API information like base URL, title, version."""
        # Get API metadata
        info = self.spec.get('info', {})
        self.api_title = info.get('title', 'Unknown API')
        self.api_version = info.get('version', '1.0.0')
        self.api_description = info.get('description', 'No description')
        
        # Get base URL from servers
        servers = self.spec.get('servers', [])
        if servers:
            self.base_url = servers[0].get('url', '')
        else:
            self.base_url = ''
        
        logger.info(f"API: {self.api_title} v{self.api_version}")
        logger.info(f"Base URL: {self.base_url}")
    
    def get_api_info(self) -> Dict[str, Any]:
        """
        Get general information about the API.
        
        Returns:
            dict: API metadata (title, version, description, base_url)
        """
        return {
            'title': self.api_title,
            'version': self.api_version,
            'description': self.api_description,
            'base_url': self.base_url
        }
    
    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """
        Get all API endpoints with their HTTP methods.
        
        Returns:
            list: List of dictionaries containing endpoint information
        """
        endpoints = []
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                # Only process HTTP methods (skip parameters, etc.)
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'summary': details.get('summary', 'No summary'),
                        'description': details.get('description', 'No description'),
                        'operation_id': details.get('operationId', f"{method}_{path}"),
                        'tags': details.get('tags', []),
                        'deprecated': details.get('deprecated', False),
                    }
                    endpoints.append(endpoint)
        
        self.endpoints = endpoints
        logger.info(f"Found {len(endpoints)} endpoints")
        return endpoints
    
    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific endpoint.
        
        Args:
            path (str): API endpoint path (e.g., '/users/{id}')
            method (str): HTTP method (e.g., 'GET', 'POST')
        
        Returns:
            dict: Detailed endpoint information including parameters and schemas
        """
        method = method.lower()
        
        # Get endpoint specification
        endpoint_spec = self.spec.get('paths', {}).get(path, {}).get(method, {})
        
        if not endpoint_spec:
            logger.warning(f"{Fore.YELLOW}Endpoint not found: {method.upper()} {path}")
            return {}
        
        # Extract all details
        details = {
            'path': path,
            'method': method.upper(),
            'summary': endpoint_spec.get('summary', ''),
            'description': endpoint_spec.get('description', ''),
            'parameters': self._extract_parameters(endpoint_spec),
            'request_body': self._extract_request_body(endpoint_spec),
            'responses': self._extract_responses(endpoint_spec),
            'security': endpoint_spec.get('security', []),
            'tags': endpoint_spec.get('tags', []),
        }
        
        return details
    
    def _extract_parameters(self, endpoint_spec: Dict) -> Dict[str, List[Dict]]:
        """
        Extract all parameters (path, query, header, cookie).
        
        Args:
            endpoint_spec (dict): Endpoint specification from OpenAPI
        
        Returns:
            dict: Parameters organized by type (path, query, header, cookie)
        """
        parameters = {
            'path': [],
            'query': [],
            'header': [],
            'cookie': []
        }
        
        for param in endpoint_spec.get('parameters', []):
            param_location = param.get('in', 'query')
            
            param_info = {
                'name': param.get('name', 'unknown'),
                'required': param.get('required', False),
                'description': param.get('description', ''),
                'deprecated': param.get('deprecated', False),
                'schema': param.get('schema', {}),
            }
            
            # Extract schema details
            schema = param.get('schema', {})
            param_info.update({
                'type': schema.get('type', 'string'),
                'format': schema.get('format'),
                'default': schema.get('default'),
                'enum': schema.get('enum'),
                'minimum': schema.get('minimum'),
                'maximum': schema.get('maximum'),
                'min_length': schema.get('minLength'),
                'max_length': schema.get('maxLength'),
                'pattern': schema.get('pattern'),
            })
            
            if param_location in parameters:
                parameters[param_location].append(param_info)
        
        return parameters
    
    def _extract_request_body(self, endpoint_spec: Dict) -> Optional[Dict]:
        """
        Extract request body schema and requirements.
        
        Args:
            endpoint_spec (dict): Endpoint specification
        
        Returns:
            dict or None: Request body information including schema
        """
        request_body = endpoint_spec.get('requestBody')
        
        if not request_body:
            return None
        
        body_info = {
            'required': request_body.get('required', False),
            'description': request_body.get('description', ''),
            'content': {}
        }
        
        # Extract content for different media types
        content = request_body.get('content', {})
        for media_type, media_spec in content.items():
            body_info['content'][media_type] = {
                'schema': media_spec.get('schema', {}),
                'examples': media_spec.get('examples', {})
            }
        
        return body_info
    
    def _extract_responses(self, endpoint_spec: Dict) -> Dict[str, Dict]:
        """
        Extract possible API responses.
        
        Args:
            endpoint_spec (dict): Endpoint specification
        
        Returns:
            dict: Response information by status code
        """
        responses = {}
        
        for status_code, response_spec in endpoint_spec.get('responses', {}).items():
            responses[status_code] = {
                'description': response_spec.get('description', ''),
                'headers': response_spec.get('headers', {}),
                'content': response_spec.get('content', {})
            }
        
        return responses
    
    def extract_schema_properties(self, schema: Dict, parent_key: str = '') -> Dict[str, Dict]:
        """
        Recursively extract properties from a JSON schema.
        This is crucial for understanding what data the API expects.
        
        Args:
            schema (dict): JSON schema object
            parent_key (str): Parent key for nested properties
        
        Returns:
            dict: Flattened property information
        """
        properties = {}
        
        if not schema:
            return properties
        
        # Handle object type
        if schema.get('type') == 'object' and 'properties' in schema:
            required_fields = schema.get('required', [])
            
            for prop_name, prop_details in schema['properties'].items():
                full_key = f"{parent_key}.{prop_name}" if parent_key else prop_name
                
                # Extract property information
                prop_info = {
                    'name': prop_name,
                    'type': prop_details.get('type', 'any'),
                    'required': prop_name in required_fields,
                    'description': prop_details.get('description', ''),
                    'format': prop_details.get('format'),
                    'default': prop_details.get('default'),
                    'enum': prop_details.get('enum'),
                    'minimum': prop_details.get('minimum'),
                    'maximum': prop_details.get('maximum'),
                    'min_length': prop_details.get('minLength'),
                    'max_length': prop_details.get('maxLength'),
                    'pattern': prop_details.get('pattern'),
                    'items': prop_details.get('items'),  # For arrays
                    'nullable': prop_details.get('nullable', False),
                }
                
                properties[full_key] = prop_info
                
                # Recursively handle nested objects
                if prop_details.get('type') == 'object':
                    nested = self.extract_schema_properties(prop_details, full_key)
                    properties.update(nested)
                
                # Handle arrays with object items
                elif prop_details.get('type') == 'array':
                    items = prop_details.get('items', {})
                    if items.get('type') == 'object':
                        nested = self.extract_schema_properties(items, f"{full_key}[]")
                        properties.update(nested)
        
        return properties
    
    def get_security_schemes(self) -> Dict[str, Dict]:
        """
        Extract security/authentication schemes defined in the API.
        
        Returns:
            dict: Security schemes (API keys, OAuth, etc.)
        """
        components = self.spec.get('components', {})
        security_schemes = components.get('securitySchemes', {})
        
        return security_schemes
    
    def print_summary(self):
        """Print a formatted summary of the parsed API."""
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}API SPECIFICATION SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
        
        # API Info
        info = self.get_api_info()
        print(f"{Fore.GREEN}Title:{Style.RESET_ALL} {info['title']}")
        print(f"{Fore.GREEN}Version:{Style.RESET_ALL} {info['version']}")
        print(f"{Fore.GREEN}Base URL:{Style.RESET_ALL} {info['base_url']}")
        print(f"{Fore.GREEN}Description:{Style.RESET_ALL} {info['description']}\n")
        
        # Endpoints
        endpoints = self.get_all_endpoints()
        print(f"{Fore.YELLOW}Total Endpoints:{Style.RESET_ALL} {len(endpoints)}\n")
        
        print(f"{Fore.CYAN}Endpoints:")
        print(f"{Fore.CYAN}{'-' * 70}{Style.RESET_ALL}")
        
        for ep in endpoints:
            method_color = {
                'GET': Fore.GREEN,
                'POST': Fore.BLUE,
                'PUT': Fore.YELLOW,
                'DELETE': Fore.RED,
                'PATCH': Fore.MAGENTA
            }.get(ep['method'], Fore.WHITE)
            
            print(f"{method_color}{ep['method']:7}{Style.RESET_ALL} {ep['path']}")
            if ep['summary']:
                print(f"         → {ep['summary']}")
        
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
    
    def export_to_json(self, output_file: str):
        """
        Export parsed API information to JSON file.
        
        Args:
            output_file (str): Path to output JSON file
        """
        data = {
            'api_info': self.get_api_info(),
            'endpoints': self.get_all_endpoints(),
            'security_schemes': self.get_security_schemes()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"{Fore.GREEN}Exported to: {output_file}")


# Helper function for standalone usage
def parse_api_spec(spec_path: str) -> APIParser:
    """
    Convenience function to parse an API specification.
    
    Args:
        spec_path (str): Path to OpenAPI spec file
    
    Returns:
        APIParser: Initialized parser object
    """
    return APIParser(spec_path)


if __name__ == "__main__":
    # Example usage
    parser = APIParser('examples/simple_api.yaml')
    parser.print_summary()