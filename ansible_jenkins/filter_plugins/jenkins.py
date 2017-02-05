# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible import errors
from distutils.version import LooseVersion


try:
    import passlib
    from passlib.hash import bcrypt
    HAS_BCRYPT = True
    HAS_TRUNCATE_ERROR = LooseVersion(passlib.__version__) >= LooseVersion('1.7.0')
except ImportError:
    HAS_BCRYPT = False


def _bcrypt_hash(password, **kwargs):
    if not HAS_BCRYPT:
        raise errors.AnsibleFilterError('jenkins_password_hash requires the passlib python module and a bcrypt backend')

    kwargs.setdefault('truncate_error', True)
    if not HAS_TRUNCATE_ERROR:
        if len(password.encode('utf-8')) > 72:
            raise errors.AnsibleFilterError('jenkins_password_hash password cannot have more than 72 bytes, '
                                            'turn off the check by adding the parameter truncate_error=False')
        del kwargs['truncate_error']

    if hasattr(bcrypt, 'hash'):
        hash_fun = bcrypt.hash
    elif hasattr(bcrypt, 'encrypt'):
        hash_fun = bcrypt.encrypt
    else:
        raise errors.AnsibleFilterError('jenkins_password_hash the installed passlib python module is not supported')

    hashed_pw = hash_fun(password, **kwargs)
    if not hashed_pw or len(hashed_pw) != len(kwargs['ident']) + 58:
        raise errors.AnsibleFilterError('jenkins_password_hash failed to hash the password')

    return hashed_pw


def jenkins_password_hash(password, **kwargs):
    '''
    Hashes password a way understood by Jenkins.

    Parameters
    ----------
    password : str
    kwargs
        Arguments supported by passlib.hash.bcrypt.hash

    Jenkins passwords are hashed with bcrypt 2a and have a specific prefix.
    '''
    kwargs.setdefault('ident', '2a')


    hashed_pw = _bcrypt_hash(password, **kwargs)
    return '#jbcrypt:' + hashed_pw



# ---- Ansible filters ----

class FilterModule(object):
    '''Filter to create password hashes compatible with Jenkins.'''

    def filters(self):
        return {
            'jenkins_password_hash': jenkins_password_hash,
        }
