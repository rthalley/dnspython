.. _installation:

Installation
============

Requirements
------------

Python 3.7 or newer.

Installation
------------

Many free operating system distributions have dnspython packaged for
you, so you should check there first.

The next easiest option is to use ``pip``::

        pip install dnspython

If ``pip`` is not available, you can download the latest zip file from
`PyPI <https://pypi.python.org/pypi/dnspython/>`_, unzip it.

On a UNIX-like system, you then run::

        sudo python setup.py install

while on a Windows system you would run::

        python setup.py install

Finally, you have the option of cloning the dnspython source from github
and building it::

        git clone https://github.com/rthalley/dnspython.git

And then run ``setup.py`` as above.

Please be aware that the master branch of dnspython on github is under
active development and may not always be stable.


Optional Modules
----------------

The following modules are optional, but recommended for full functionality.

If ``httpx`` is installed, then DNS-over-HTTPS will be available.

If ``cryptography`` is installed, then dnspython will be
able to do low-level DNSSEC signature generation and validation.

If ``idna`` is installed, then IDNA 2008 will be available.

If ``aioquic`` is installed, the DNS-over-QUIC will be available.
