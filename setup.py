from setuptools import setup, find_packages
import io

with io.open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="firebase_rfs",
    version="1.2.0",
    packages=find_packages(),
    install_requires=[
        'rich>=13.7.0',
        'requests>=2.31.0',
        'firebase-admin>=6.4.0',
        'python-dateutil>=2.8.2',
        'cryptography>=41.0.5',
        'packaging>=21.0',
        'tqdm>=4.66.2',
        'argparse>=1.4.0',
        'beautifulsoup4>=4.12.3',
        'lxml>=5.1.0',
        'pyjwt>=2.8.0',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'pyyaml>=6.0.1',
        'pillow>=10.2.0',
        'bandit>=1.7.7',
        'safety>=2.3.5',
        'python-nmap>=0.7.1',
        'dnspython>=2.6.1',
        'pyOpenSSL>=24.0.0',
        'sslyze>=5.2.0',
        'python-whois>=0.8.0',
    ],
    extras_require={
        'dev': [
            'pytest>=8.0.2',
            'black>=24.2.0',
            'mypy>=1.8.0',
            'flake8>=7.0.0',
            'isort>=5.13.2',
        ],
    },
    entry_points={
        'console_scripts': [
            'firerfs=firebase_rfs.cli:main',
        ],
    },
    author="FireRFS Team",
    author_email="support@firerfs.com",
    description="Advanced Firebase Security Assessment Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/firerfs/firerfs",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
) 