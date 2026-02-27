import json
from pathlib import Path
from parser.api_parser import APIParser as OpenAPIParser
from parser.postman_parser import PostmanCollectionParser


class ParserFactory:

    @staticmethod
    def create_parser(spec_path: str, base_url=None):

        if spec_path.startswith("http"):
            return OpenAPIParser(spec_path, base_url)

        path = Path(spec_path)

        if not path.exists():
            raise FileNotFoundError("Spec file not found")

        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception:
                raise ValueError("Invalid JSON file")

        # ---- FORMAT DETECTION ----

        if "openapi" in data or "swagger" in data:
            return OpenAPIParser(spec_path, base_url)

        if "item" in data and "info" in data:
            return PostmanCollectionParser(spec_path)

        raise ValueError("Unknown API specification format")