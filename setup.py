from setuptools import setup, find_packages
from os.path import join, dirname

setup(
    name = "httpclient",
    version = "0.1",
    packages = find_packages()+[""],  # include all packages under src    
    include_package_data = True,    # include everything in source control  
    
    #install_requires=['sys', 'math', 'os', "logging", "multiprocessing", "math"],
    
    # metadata for upload to PyPI
    author = "Kyrylo Kukhelnyi",
    author_email = "mrkiril@ukr.net",
    description = "HTTP lib with keep alive connections",    
    keywords = "http request keep alive",
    test_suite='tests.test_lib',
    url="www.google.com.ua",
    long_description=open(join(dirname(__file__), 'README.txt')).read(),
    license = "BSD",
)