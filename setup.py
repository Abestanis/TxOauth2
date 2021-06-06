from setuptools import setup

setup(
    name='txoauth2',
    version='1.2.1',
    author='Sebastian Scholz',
    author_email='abestanis.gc@gmail.com',
    description='A module that allows implementing OAuth2 with twisted',
    long_description='A module that allows implementing an OAuth2 authorization and token '
                     'endpoint with twisted. See the Github repository for more info.',
    license='MIT',
    keywords=['OAuth2', 'twisted'],
    url='https://github.com/Abestanis/TxOauth2',
    packages=['txoauth2'],
    install_requires=['twisted'],
    extras_require={
        ':python_version < "3.0"': [
            'enum34',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Framework :: Twisted',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
)
