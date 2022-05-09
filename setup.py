import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="encryptAgit",
    version="0.0.5",
    author="Josh Pitts https://twitter.com/ausernamedjosh",
    author_email="the.midnite.runr@gmail.com",
    description="Encrypt your git repo",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secretsquirrel/encryptAgit",
    project_urls={
        "Bug Tracker": "https://github.com/secretsquirrel/encryptAgit/issues",
    },
    packages=setuptools.find_packages(),
    py_modules=['encryptAgit'],
    package_dir={"":"encryptAgit/src"},
    entry_points = {'console_scripts': ['encryptAgit = encryptAgit:main']},
    python_requires=">=3.7",
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
