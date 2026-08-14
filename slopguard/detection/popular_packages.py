from typing import Set

POPULAR_PYPI_PACKAGES: Set[str] = {
    "requests", "urllib3", "pandas", "numpy", "scipy", "scikit-learn", "matplotlib",
    "pydantic", "fastapi", "flask", "django", "pytest", "click", "setuptools",
    "wheel", "boto3", "sqlalchemy", "transformers", "torch", "tensorflow",
    "pillow", "beautifulsoup4", "jinja2", "pip", "asyncio", "celery", "redis",
    "httpx", "aiohttp", "black", "flake8", "mypy", "pyyaml", "scikit-bio",
    "opentelemetry-api", "protobuf", "typing-extensions", "certifi", "idna",
    "chardet", "six", "python-dateutil", "urllib", "importlib-metadata",
    "cryptography", "paramiko", "pymongo", "psycopg2", "pillow", "joblib"
}

POPULAR_NPM_PACKAGES: Set[str] = {
    "react", "react-dom", "react-router", "react-router-dom", "jscodeshift",
    "react-codemod", "express", "lodash", "axios", "typescript", "vite", "next",
    "vue", "svelte", "webpack", "babel", "tsup", "esbuild", "tailwindcss",
    "prettier", "eslint", "jest", "vitest", "commander", "chalk", "inquirer",
    "rxjs", "date-fns", "moment", "uuid", "cors", "dotenv", "fs-extra",
    "body-parser", "cookie-parser", "jsonwebtoken", "bcrypt", "mongoose",
    "typeorm", "prisma", "graphql", "apollo-client", "redux", "zustand",
    "styled-components", "emotion", "lucide-react", "classnames", "clsx",
    "ts-node", "nodemon", "rimraf", "cross-env", "yargs", "semver"
}


def get_popular_packages(ecosystem: str) -> Set[str]:
    eco = ecosystem.lower()
    if eco in ("pypi", "python"):
        return POPULAR_PYPI_PACKAGES
    elif eco in ("npm", "node", "typescript", "javascript"):
        return POPULAR_NPM_PACKAGES
    return POPULAR_PYPI_PACKAGES.union(POPULAR_NPM_PACKAGES)
