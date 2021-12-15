#!/usr/bin/env python3

import argparse
import base36
from botocore.client import Config
import boto3
import calendar
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from datetime import datetime, date
import hashlib
from io import BytesIO
import json
import lzma
from multiprocessing import Pool
import os
from pathlib import Path, PurePath
import re
import sys
from tempfile import NamedTemporaryFile


ENCRYPTED_EXTENSION = 'xz-aes'


class LocalStorage(object):
    """
    Storage for the local file system. 
    """
    def __init__(self, local_path):
        self.path = Path(local_path)
    
    def list(self, extension=None):
        """
        Returns a list of files stored by the storage, relative to the storage root.
        """
        self.path.mkdir(parents=True, exist_ok=True)
        return [str(p.relative_to(self.path)) 
            for p in self.path.rglob('*.%s' % extension if extension else '*')
            if not p.is_dir()]
    
    def list_iter(self):
        """
        Iterates through the list of files stored by the storage and yields StorageFileState.
        """
        for storage_filename in self.list():
            s = (self.path / storage_filename).stat()
            yield StorageFileState(
                storage_filename=storage_filename,
                last_modified=int(s.st_mtime),
                size=s.st_size)
    
    def write(self, storage_filename, data):
        """
        Atomically write the data to the storage.
        """
        # ensure the parent folder(s) exit
        p = self.path / storage_filename
        p.parent.mkdir(parents=True, exist_ok=True)
        
        # store the data in a temporary file and flush the data to disk
        f = NamedTemporaryFile(delete=False)
        f.write(data)
        f.flush()
        os.fsync(f.fileno()) 
        f.close()
        
        # atomically rename the temporary file to our destination file
        os.rename(f.name, str(p))
    
    def read(self, storage_filename):
        """
        Returns the data of the storage file.
        """
        with open(str(self.path / storage_filename), 'rb') as f:
            return f.read()
    
    def rename(self, from_storage_filename, to_storage_filename):
        """
        Renames from a storage filename to another name.
        """
        os.rename(str(self.path / from_storage_filename), str(self.path / to_storage_filename))
    
    def remove(self, storage_filename):
        """
        Removes a file from the storage.
        """
        os.remove(str(self.path / storage_filename))


class S3Storage(object):
    """
    Storage for an s3 bucket. 
    """
    def __init__(self, aws_access_key_id, aws_secret_access_key, s3_bucket, base_path=None,
            endpoint_url=None, signature_version=None, region_name=None):
        self.s3_args = {
            'aws_access_key_id': aws_access_key_id, 
            'aws_secret_access_key': aws_secret_access_key,
            'signature_version': signature_version,
            'endpoint_url': endpoint_url,
            'region_name': region_name,
            }
        self.s3_bucket = s3_bucket
        self.base_path = PurePath((base_path or '').lstrip('/'))
        
    def list(self, extension=None):
        """
        Returns a list of files stored by the storage, relative to the storage root.
        """
        extension = '.' + extension if extension else None
        return [v[0] for v in self._list()
            if extension is None or os.path.splitext(v[0])[1] == extension]
    
    def list_iter(self):
        """
        Iterates through the list of files stored by the storage and yields StorageFileState.
        """
        for storage_filename, obj in self._list():
            yield StorageFileState(
                storage_filename=storage_filename,
                last_modified=calendar.timegm(obj.last_modified.utctimetuple()),
                size=obj.size)
    
    def write(self, storage_filename, data):
        """
        Atomically write the data to the storage.
        """
        self._bucket().upload_fileobj(BytesIO(data), str(self.base_path / storage_filename))
        
    def read(self, storage_filename):
        """
        Returns the data of the storage file.
        """
        data_io = BytesIO()
        self._bucket().download_fileobj(str(self.base_path / storage_filename), data_io)
        return data_io.getvalue()
    
    def rename(self, from_storage_filename, to_storage_filename):
        """
        Renames from a storage filename to another name.
        """
        self._bucket().Object(str(self.base_path / to_storage_filename)).copy_from(CopySource={
            'Bucket': self.s3_bucket, 'Key': str(self.base_path / from_storage_filename)})
        self._bucket().Object(str(self.base_path / from_storage_filename)).delete()
    
    def remove(self, storage_filename):
        """
        Removes a file from the storage.
        """
        self._bucket().Object(str(self.base_path / storage_filename)).delete()
    
    def _bucket(self):
        """
        Internally used to return the boto3 bucket.
        """
        args = dict(self.s3_args)
        signature_version = args.pop('signature_version')
        s3 = boto3.resource('s3', **dict(args, 
            config=Config(signature_version=signature_version) if signature_version else None))
        return s3.Bucket(self.s3_bucket)
    
    def _list(self):
        """
        Internally used by list and list_iter.
        """
        if str(self.base_path) != '.':
            it = self._bucket().objects.filter(Prefix=str(self.base_path) + '/')
        else:
            it = self._bucket().objects.all()
            
        for obj in it:
            if obj.key.endswith('/'):
                continue # ignore folders
            yield str(PurePath(obj.key).relative_to(self.base_path)), obj    


StorageFileState = namedtuple('StorageFileState', ['storage_filename', 'last_modified', 'size'])

EncryptedFileState = namedtuple('EncryptedFileState', ['encrypted_filename', 'original_filename', 
    'last_modified', 'original_size', 'original_md5', 'deleted_date'], defaults=[None] * 6)


def encrypted_filename_to_encrypted_file_state(encrypted_filename):
    """
    Splits the filename of an encrypted file into an EncryptedFileState.
    The state of an encrypted file is stored within it's filename.
    """
    original_filename, last_modified, original_size, original_md5, deleted_date, extension = \
        encrypted_filename.rsplit('.', 5)
    assert extension == ENCRYPTED_EXTENSION
    return EncryptedFileState(encrypted_filename=encrypted_filename,
        original_filename=original_filename,
        last_modified=base36.loads(last_modified), 
        original_size=base36.loads(original_size), 
        original_md5=base36.loads(original_md5),
        deleted_date=base36.loads(deleted_date))


def encrypted_file_state_to_encrypted_filename(encrypted_state=None, **kwargs):
    """
    Returns the filename that should be used to store the encrypted file on the storage.
    """
    if encrypted_state and kwargs:
        encrypted_state = EncryptedFileState(**dict(encrypted_state._asdict(), **kwargs))
    elif kwargs:
        encrypted_state = EncryptedFileState(**kwargs)
    
    return '.'.join([
        encrypted_state.original_filename,
        base36.dumps(encrypted_state.last_modified),
        base36.dumps(encrypted_state.original_size),
        base36.dumps(encrypted_state.original_md5),
        base36.dumps(encrypted_state.deleted_date),
        ENCRYPTED_EXTENSION,
        ])


def get_aes_key(encryption_password, salt):
    """
    Derives an AES key from an encryption password and salt.
    """
    return PBKDF2(encryption_password, salt, 32, count=100000, hmac_hash_module=SHA512)


def get_aes_cipher(aes_key, nonce=None):
    """
    Returns the AES-GCM cipher to use for a given AES key.
    """
    return AES.new(aes_key, AES.MODE_GCM, nonce)


def download_object(index, config, src_storage, dest_storage, original_state):
    """
    Downloads an object from s3, encrypts it using AES-256-GCM and stores it on the storage.
    """
    print('[{0}] Downloading {1}...'.format(index + 1, original_state.storage_filename))
    
    # download/read the original file from the source storage
    original_data = src_storage.read(original_state.storage_filename)
    
    # determine the size and md5 of the data before encrypted
    assert original_state.size == len(original_data), \
        'Download failed for [%s]. Size mismatch. Expected %s, got %s!' % (
            original_state.storage_filename, original_state.size, len(original_data))
    original_md5 = int(hashlib.md5(original_data).hexdigest(), 16)
    
    # compress the file using lzma (xz)
    compressed_data = lzma.compress(original_data)
    del original_data
    
    # derive an encryption key from the users password 
    salt = get_random_bytes(16)
    aes_key = get_aes_key(config['encryption_password'], salt)
    
    # encrypt the data using aes-256-gcm
    cipher = get_aes_cipher(aes_key)
    ciphertext, tag = cipher.encrypt_and_digest(compressed_data)
    del compressed_data
    
    encrypted_io = BytesIO()
    [encrypted_io.write(x) for x in (salt, cipher.nonce, tag, ciphertext)]
    
    # write the encrypted file to the storage
    encrypted_filename = encrypted_file_state_to_encrypted_filename(
        original_filename=original_state.storage_filename,
        last_modified=original_state.last_modified, 
        original_size=original_state.size, 
        original_md5=original_md5,
        deleted_date=0)
    dest_storage.write(encrypted_filename, encrypted_io.getvalue())


def do_backup(config, src_storage, dest_storage):
    """
    Performs a backup to the storage.
    """
    with Pool(config.get('backup_processes', 5)) as pool:
        processes = []
        
        # load all files on the storage and their state
        print('Listing files on destination storage...')
        
        dest_storage_files = {s.original_filename: s 
            for s in (encrypted_filename_to_encrypted_file_state(f) 
                for f in dest_storage.list(extension=ENCRYPTED_EXTENSION))}
        src_storage_files = set()
        
        print('Listing files on source storage and queuing downloads...')
        
        ignore_regexes = [re.compile(r) for r in config.get('ignore_regex', [])]
        
        for i, original_state in enumerate(src_storage.list_iter()):
            if any(r.match(original_state.storage_filename) for r in ignore_regexes):
                continue # the user has requested to ignore
            
            src_storage_files.add(original_state.storage_filename)
            encrypted_state = dest_storage_files.get(original_state.storage_filename)
            
            # if the file has never been downloaded, then queue for downloading
            # or if the file has changed size or been modified, then queue for downloading
            if (encrypted_state is None or 
                    encrypted_state.original_size != original_state.size or 
                    encrypted_state.last_modified != original_state.last_modified):
                processes.append(pool.apply_async(download_object,
                    [i, config, src_storage, dest_storage, original_state]))
                
                # remove any old version of the file
                if encrypted_state is not None:
                    print('[{0}] Removing old {1} ({2} bytes, modified {3}, deleted {4})...'.format(
                        i + 1, original_state.storage_filename, encrypted_state.original_size, 
                        datetime.utcfromtimestamp(encrypted_state.last_modified), 
                        encrypted_state.deleted_date))
                    dest_storage.remove(encrypted_state.encrypted_filename)
                    del dest_storage_files[original_state.storage_filename]
            
            # if the file has been deleted, then mark it as not deleted
            elif encrypted_state.deleted_date:
                print('[{0}] Undeleting {1}...'.format(i + 1, original_state.storage_filename))
                dest_storage.rename(encrypted_state.encrypted_filename, 
                    encrypted_file_state_to_encrypted_filename(encrypted_state, deleted_date=0))
        
        # mark all missing files that exist on the storage as deleted
        today = int(date.today().strftime('%Y%m%d'))
        
        for s3_key in set(dest_storage_files) - src_storage_files:
            print('[{0}] Deleting {1}...'.format(i + 1, original_state.storage_filename))
            encrypted_state = dest_storage_files[s3_key]
            dest_storage.rename(encrypted_state.encrypted_filename,
                encrypted_file_state_to_encrypted_filename(encrypted_state, deleted_date=today))
        
        # wait for all processes to finish and raise any exceptions they raise
        print('Listing complete! Waiting for downloads to finish...')
        for process in processes:
            process.get() # re-raises any exceptions


def restore_object(index, config, dest_storage, encrypted_state, restore_storage=None, verify=False):
    """
    Restores an object from the storage to the local file system.
    """
    print('[{0}] Restoring {1}...'.format(index + 1, encrypted_state.original_filename))
    
    # read the encrypted file and break it into it's parts
    encrypted_io = BytesIO(dest_storage.read(encrypted_state.encrypted_filename))
    salt, nonce, tag, ciphertext = [encrypted_io.read(x) for x in (16, 16, 16, -1)]
    del encrypted_io
    
    # derive an encryption key from the users password 
    aes_key = get_aes_key(config['encryption_password'], salt)
    
    # decrypt the data using aes-256-gcm
    cipher = get_aes_cipher(aes_key, nonce)
    compressed_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # decompress the file using lzma (xz)
    original_data = lzma.decompress(compressed_data)
    
    # verify the contents
    error = None
    original_md5 = int(hashlib.md5(original_data).hexdigest(), 16)
    
    if encrypted_state.original_size != len(original_data):
        error = 'Restore failed for [%s]. Size mismatch. Expected %s, got %s!' % (
            encrypted_state.original_filename, encrypted_state.original_size, len(original_data))
    
    elif encrypted_state.original_md5 != original_md5:
        error = 'Restore failed for [%s]. MD5 mismatch. Expected %s, got %s!' % (
            encrypted_state.original_filename, encrypted_state.original_md5, original_md5)
    
    if error:
        if verify:
            print('[{0}] {1}'.format(index + 1, error), file=sys.stderr)
            return
        else:
            raise ValueError(error) # backup is corrupt, so bail
    
    if verify:
        print('[{0}] OK'.format(index + 1))
    else:
        # save the file to it's destination
        restore_storage.write(encrypted_state.original_filename, original_data)


def do_restore(config, dest_storage, restore_storage=None, restore_deleted=False, verify=False):
    """
    Performs a restore from the storage to a directory, optionally including deleted files.
    """
    with Pool(config.get('restore_processes', 8)) as pool:
        processes = []
        
        print('Listing files on destination storage...')
        
        for i, encrypted_state in enumerate([encrypted_filename_to_encrypted_file_state(f) 
                for f in dest_storage.list(extension=ENCRYPTED_EXTENSION)]):
            if not verify and encrypted_state.deleted_date and not restore_deleted:
                continue # skip deleted (except when verifying)
            processes.append(pool.apply_async(restore_object,
                [i, config, dest_storage, encrypted_state, restore_storage, verify]))            
        
        # wait for all processes to finish and raise any exceptions they raise
        print('Listing complete! Waiting for decryption to finish...')
        for process in processes:
            process.get() # re-raises any exceptions            


def main():
    """
    Runs the backup.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.json',
        help='Specify the path to the config file.')
    parser.add_argument('--verify', action='store_true',
        help='Verifies the integrity of a backup by decrypting and verifying hashes.')
    parser.add_argument('--restore', action='store_true',
        help='Perform a restore instead of a backup.')
    parser.add_argument('--restore-deleted', action='store_true',
        help='Restore deleted files during the restore. Not enabled by default.')
    args = parser.parse_args()
    
    with open(args.config, 'rb') as f:
        config = json.load(f)
    
    if config['src'].get('local_path'):
        src_storage = LocalStorage(**config['src'])
    elif config['src'].get('s3_bucket'):
        src_storage = S3Storage(**config['src'])
    
    if config['dest'].get('local_path'):
        dest_storage = LocalStorage(**config['dest'])
    elif config['dest'].get('s3_bucket'):
        dest_storage = S3Storage(**config['dest'])
    
    if config['restore'].get('local_path'):
        restore_storage = LocalStorage(**config['restore'])
    elif config['restore'].get('s3_bucket'):
        restore_storage = S3Storage(**config['restore'])
    
    if args.verify:
        do_restore(config, dest_storage, verify=True)
    elif args.restore:
        do_restore(config, dest_storage, restore_storage=restore_storage, 
            restore_deleted=args.restore_deleted)
    else:
        do_backup(config, src_storage, dest_storage)
    
    print('Done!')


if __name__ == '__main__':
    sys.exit(main())