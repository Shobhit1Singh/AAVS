import unittest
# from parser.api_parser import APIParser
from pathlib import Path
import sys
sys.path.insert(0, 'C:\\AAVS')
from parser.api_parser import APIParser

class TestAPIParser(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.parser = APIParser('examples/simple_api.yaml')
    
    def test_api_info(self):
        """Test API information extraction"""
        info = self.parser.get_api_info()
        self.assertEqual(info['title'], 'Simple User API')
        self.assertEqual(info['version'], '1.0.0')
        self.assertIn('https://api.example.com', info['base_url'])
    
    def test_endpoints_count(self):
        """Test endpoint extraction"""
        endpoints = self.parser.get_all_endpoints()
        self.assertEqual(len(endpoints), 5)
    
    def test_endpoint_methods(self):
        """Test HTTP methods are correctly extracted"""
        endpoints = self.parser.get_all_endpoints()
        methods = [ep['method'] for ep in endpoints]
        self.assertIn('GET', methods)
        self.assertIn('POST', methods)
        self.assertIn('PUT', methods)
        self.assertIn('DELETE', methods)
    
    def test_endpoint_details(self):
        """Test detailed endpoint information"""
        details = self.parser.get_endpoint_details('/users', 'POST')
        self.assertIsNotNone(details)
        self.assertEqual(details['method'], 'POST')
        self.assertIn('request_body', details)
    
    def test_schema_extraction(self):
        """Test schema property extraction"""
        details = self.parser.get_endpoint_details('/users', 'POST')
        schema = details['request_body']['content']['application/json']['schema']
        properties = self.parser.extract_schema_properties(schema)
        
        self.assertIn('username', properties)
        self.assertIn('email', properties)
        self.assertTrue(properties['username']['required'])


if __name__ == '__main__':
    unittest.main()