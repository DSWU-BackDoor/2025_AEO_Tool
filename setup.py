from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="aeo-security-tool",
    version="1.0.0",
    author="Your Organization",
    author_email="security-tool@your-org.com",
    description="SBOM 기반 AEO, ISMS 통합 보안 검증 자동화 도구",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/aeo-security-tool",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "cyclonedx-python-lib>=5.0.0",
        "packageurl-python>=0.11.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "requests>=2.31.0",
        "python-dateutil>=2.8.2",
        "reportlab>=4.0.0",
        "jinja2>=3.1.2",
        "python-dotenv>=1.0.0",
        "PyYAML>=6.0",
        "colorlog>=6.8.0",
        "tqdm>=4.66.0",
    ],
    entry_points={
        "console_scripts": [
            "aeo-tool=aeo_tool.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "aeo_tool": [
            "report/templates/*.html",
        ],
    },
)