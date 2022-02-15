#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
import sys


def main():
    """
    Generates a salt to be used for the "encryption_salt" config parameter. 
    """
    salt = get_random_bytes(16).hex()
    
    print('')
    print('For config.json, copy this line and paste into config.json:')
    print('"encryption_salt": "%s",' % salt)
    print('')
    print('For config environment variables, use this variable:')
    print('ENCRYPTION_SALT=%s' % salt)
    print('')


if __name__ == '__main__':
    sys.exit(main())
