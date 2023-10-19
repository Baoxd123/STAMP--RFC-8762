from setuptools import setup
from setuptools import find_packages
  
setup(
    name='stamp',
    version='0.1',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=[
        'astropy==5.1',
        'grpcio>=1.53.0',
        'grpcio-tools==1.50.0',
        'netifaces==0.11.0',
        'numpy==1.22.4',
        'packaging==23.0',
        'pandas==2.0.0',
        'protobuf==4.21.9',
        'pyerfa==2.0.0.1',
        'python-dateutil==2.8.2',
        'pytz==2023.3',
        'PyYAML==6.0',
        'scapy==2.4.4',
        'six==1.14.0',
        'tzdata==2023.3'
    ],
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'STAMPSender = ProbingAgent.utility.STAMPSender:main',
            'STAMPReflector = ProbingAgent.utility.STAMPReflector:main'
        ]
    }
)