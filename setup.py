from distutils.core import setup

setup(
    name='txoauth2',
    version='0.3',
    author='Sebastian Scholz',
    author_email='abestanis.gc@gmail.com',
    description='A module that allows implementing OAuth2 with twisted',
    long_description='A module that allows implementing an OAuth2 authorization and token '
                     'endpoint with twisted',
    license='MIT',
    keywords=['OAuth2', 'twisted'],
    url='https://github.com/Abestanis/TwistedOAuth2',
    packages=['txoauth2'],
    install_requires=['twisted']
)
