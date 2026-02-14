"""
API Security Fuzzer - Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text() if readme_file.exists() else ''

setup(
    name='api-security-fuzzer',
    version='1.0.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='Automated API security testing and vulnerability scanner',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/api-security-fuzzer',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'prance>=23.6.21.0',
        'requests>=2.31.0',
        'pyyaml>=6.0.1',
        'jsonschema>=4.20.0',
        'openapi-spec-validator>=0.7.1',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'rich>=13.7.0',
        'click>=8.1.7',
        'faker>=22.0.0',
        'hypothesis>=6.96.0',
        'httpx>=0.26.0',
        'pyjwt>=2.8.0',
        'cryptography>=42.0.0',
        'scikit-learn>=1.4.0',
        'joblib>=1.3.2',
        'jinja2>=3.1.3',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.7.0',
            'flake8>=6.1.0',
        ],
        'test-api': [
            'flask>=3.0.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'apifuzz=cli.main:cli',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.8',
    keywords='api security testing fuzzing vulnerability scanner pentesting',
)