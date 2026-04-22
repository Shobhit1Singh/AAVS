import json
import yaml
from pathlib import Path

from parser.api_parser import APIParser as OpenAPIParser
from parser.postman_parser import PostmanCollectionParser


class ParserFactory:

    @staticmethod
    def create_parser(spec_path: str, base_url=None):

        # Remote URL spec
        if spec_path.startswith("http"):
            return OpenAPIParser(spec_path, base_url)

        path = Path(spec_path)

        if not path.exists():
            raise FileNotFoundError("Spec file not found")

        ext = path.suffix.lower()

        with open(path, "r", encoding="utf-8") as f:
            try:
                if ext == ".json":
                    data = json.load(f)

                elif ext in [".yaml", ".yml"]:
                    data = yaml.safe_load(f)

                else:
                    raise ValueError(
                        "Unsupported file format. Use .json, .yaml, or .yml"
                    )

            except Exception as e:
                raise ValueError(f"Invalid specification file: {str(e)}")

        if not isinstance(data, dict):
            raise ValueError("Invalid spec structure")

        # ---- FORMAT DETECTION ----

        if "openapi" in data or "swagger" in data:
            return OpenAPIParser(spec_path, base_url)

        if "item" in data and "info" in data:
            return PostmanCollectionParser(spec_path)

        raise ValueError("Unknown API specification format")