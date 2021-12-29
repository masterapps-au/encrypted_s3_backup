#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
import sys


def main():
    """
    Generates a salt to be used for the "encryption_salt" config parameter. 
    """
    print('"encryption_salt": "%s",' % get_random_bytes(16).hex())


if __name__ == '__main__':
    sys.exit(main())
