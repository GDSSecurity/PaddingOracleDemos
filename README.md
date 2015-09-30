PaddingOracleDemos
===========

Example web application vulnerable to the Padding Oracle attack and scripts to exploit it.

__Web application__

Usage:
```
# python pador.py
```

Dependencies:
*   https://pypi.python.org/pypi/cryptography/
*   https://pypi.python.org/pypi/Flask

Testing:
```
# curl http://127.0.0.1:5000/encrypt?plain=ApplicationUsername%3Duser%26Password%3Dsesame
crypted: 484b850123a04baf15df9be14e87369[..]

# curl http://127.0.0.1:5000/echo?cipher=484b850123a04baf15df9be14e87369[..]
decrypted: ApplicationUsername=user&Password=sesame

# curl http://127.0.0.1:5000/check?cipher=484b850123a04baf15df9be14e87369[..]
decrypted: ApplicationUsername=user&Password=sesame
parsed: {'Password': ['sesame'], 'ApplicationUsername': ['user']}
```

__Exploit scripts__

The files in ```python-exploit/``` contain examples on how to exploit the web application using [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle).

Usage:
```
# python http-advanced.py

# python http-simple.py
```

Dependencies:
*   https://pypi.python.org/pypi/paddingoracle