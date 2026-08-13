from setuptools import setup, find_packages

setup(
    name="trirecon",
    version="1.0.0",
    description="Modular CLI security reconnaissance toolkit",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/YOUR-USERNAME/triRecon",
    license="MIT",
    packages=find_packages(),
    package_data={
        "": ["wordlists/*.txt"],
    },
    install_requires=[
        "click>=8.1,<9",
        "rich>=13.0,<14",
        "requests>=2.31,<3",
        "urllib3>=2.0,<3",
    ],
    entry_points={
        "console_scripts": [
            "trirecon=trirecon:cli",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
