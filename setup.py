from setuptools import find_packages, setup


setup(
    name="agent-memory-audit",
    version="0.1.0",
    description="Audit agent memory files for stale facts, missing sources, and secret markers.",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "agent-memory-audit=agent_memory_audit.cli:main",
        ],
    },
)
