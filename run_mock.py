from fastapi import FastAPI
import json

app = FastAPI()

with open("collection.json") as f:
    spec = json.load(f)

for path, methods in spec["paths"].items():
    for method in methods:
        def handler():
            return {"mock": "ok"}
        app.add_api_route(path.replace("{{", "{").replace("}}", "}"), handler, methods=[method.upper()])

