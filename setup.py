from setuptools import setup, find_packages

setup(
    name="tracksnipper",
    version="1.0.0",
    author="Anirban",
    author_email="fairytailanirbans@gmail.com",
    description="CLI tool for detecting and logging suspicious Linux system activity",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Anirban780/TrackSnipper",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "tracksnipper=tracksnipper.cli:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Environment :: Console",
    ],
    python_requires='>=3.7',
)
