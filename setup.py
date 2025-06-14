import setuptools

with open("README.md", encoding="utf-8") as fp:
    long_description = fp.read()

setuptools.setup(
    name="galv_cdk",
    version="0.1.0",
    description="Deploy Galv to AWS with CDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Galv Team",
    package_dir={"": "galv_cdk"},
    packages=setuptools.find_packages(where="galv_cdk"),
    install_requires=[
        "aws-cdk-lib~=2.0",
        "constructs~=10.0",
        "cdk-nag~=2.35",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
)
