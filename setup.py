from setuptools import setup

setup(
    name='cienasaos10ncc',
    version='0.8.0',    
    description='Backend Library to interface with Ciena SAOS 10 devices.',
    url='https://github.com/braincan/cienasaos10ncc',
    author='Lucas Wood',
    author_email='lucasw@lucaswood.net',
    license='Apache License',
    packages=['cienasaos10ncc'],
    install_requires=['ncclient>=0.6.15',
                      'jinja2', 
                      'xmltodict'                    
                      ],

    classifiers=[
        'Development Status :: 1 - Alpha',
        'Intended Audience :: Network Operators',
        'License :: OSI Approved :: Apache License', 
        "Environment :: Console", 
        'Operating System :: OS Independent',        
        'Programming Language :: Python :: 3'
    ],
)
