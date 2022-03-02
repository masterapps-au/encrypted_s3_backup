#!/usr/bin/env python3

import argon2
from argon2.profiles import RFC_9106_LOW_MEMORY
import argparse
from botocore.client import Config
from botocore.exceptions import ClientError
import boto3
import calendar
from collections import namedtuple
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from datetime import datetime, date
from functools import reduce
import gzip
import hashlib
from io import BytesIO, SEEK_CUR, SEEK_END
import json
import lzma
from mom.codec import base36
from multiprocessing import Pool
import operator
import os
from pathlib import Path, PurePath
import re
import sys
from tempfile import gettempdir, NamedTemporaryFile, _TemporaryFileWrapper


#
# Constants
#
ENCRYPTED_EXTENSION = 'enc'
CHUNK_SIZE = 10 * 1024 * 1024 # 10MB chunks
IN_MEMORY_MAX_SIZE = 100 * 1024 * 1024 # process files <= 100MB entirely in memory
LZMA_MAX_SIZE = 10 * 1024 * 1024 # compress files > 10MB using gzip instead of lzma (for speed)
DEFAULT_ENCRYPTION_TYPE = 'aes'

STORAGES = [] # NOTE: populated below
CONFIG_ALL = [
    'encryption_password',
    'encryption_salt',
    'encrypt_filenames',
    'backup_processes',
    'restore_processes',
    'deleted_keep_days',
    'ignore_regex',
    'lzma_level',
    'gzip_level',
    'compress',
    'encrypt',
    'encryption_type',    
    ] # NOTE: extended by storages below


#
# Tuples
#
StorageFileState = namedtuple('StorageFileState', ['storage_filename', 'last_modified', 'size'])

EncryptedFileState = namedtuple('EncryptedFileState', ['encrypted_filename', 'original_filename', 
    'last_modified', 'original_size', 'original_md5', 'deleted_date'], defaults=[None] * 6)


#
# Storages
#
class LocalStorage(object):
    """
    Storage for the local file system. 
    """
    ARGS = ['local_path']
    
    def __init__(self, local_path):
        self.path = Path(local_path)
    
    def init(self):
        """
        Initialise the storage. Only called once per run.
        """
        pass    
    
    def list(self, extension=None):
        """
        Returns a list of files stored by the storage, relative to the storage root.
        """
        self.path.mkdir(parents=True, exist_ok=True)
        return [str(p.relative_to(self.path)) 
            for p in self.path.rglob('*.%s' % extension if extension else '*')
            if p.is_file() and p.exists()]
    
    def list_iter(self, extension=None):
        """
        Iterates through the list of files stored by the storage and yields StorageFileState.
        """
        for storage_filename in self.list(extension=extension):
            s = (self.path / storage_filename).stat()
            yield StorageFileState(
                storage_filename=storage_filename,
                last_modified=int(s.st_mtime),
                size=s.st_size)
    
    def write(self, storage_filename, f):
        """
        Atomically write the data to the storage.
        """
        # ensure the parent folder(s) exit
        p = self.path / storage_filename
        p.parent.mkdir(parents=True, exist_ok=True)
        
        if isinstance(f, _TemporaryFileWrapper):
            pass # already a temporary file, so just rename it
        else:
            # store the data in a temporary file
            f.seek(0)
            f2 = NamedTemporaryFile(delete=False)
            for chunk in read_chunks(f):
                f2.write(chunk)
            f = f2
        
        # ensure the data is flushed to disk before we rename
        f.flush()
        os.fsync(f.fileno()) 
        f.close()
        
        # atomically rename the temporary file to our destination file
        os.rename(f.name, str(p))
    
    def read(self, storage_filename, size_hint):
        """
        Returns the data of the storage file as a file-like object.
        The file-like object must be compatible with close_temp_io.
        """
        return open(str(self.path / storage_filename), 'rb')
    
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

STORAGES.append(LocalStorage)


class S3Storage(object):
    """
    Storage for an s3 bucket. 
    """
    ARGS = ['aws_access_key_id', 'aws_secret_access_key', 's3_bucket', 'base_path', 'endpoint_url',
        'signature_version', 'region_name']
    
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
    
    def init(self):
        """
        Initialise the storage. Only called once per run.
        """
        # create the bucket if it doesn't exist
        bucket = self._bucket()
        try:
            bucket.meta.client.head_bucket(Bucket=bucket.name)
        except ClientError:
            log('Bucket "{0}" does not exist. Creating...'.format(bucket.name))
            bucket.meta.client.create_bucket(Bucket=bucket.name)
    
    def list(self, extension=None):
        """
        Returns a list of files stored by the storage, relative to the storage root.
        """
        return [v[0] for v in self._list(extension=extension)]
    
    def list_iter(self, extension=None):
        """
        Iterates through the list of files stored by the storage and yields StorageFileState.
        """
        for storage_filename, obj in self._list(extension=extension):
            yield StorageFileState(
                storage_filename=storage_filename,
                last_modified=calendar.timegm(obj.last_modified.utctimetuple()),
                size=obj.size)
    
    def write(self, storage_filename, f):
        """
        Atomically write the data to the storage.
        """
        f.seek(0)
        self._bucket().upload_fileobj(f, str(self.base_path / storage_filename))
        
    def read(self, storage_filename, size_hint):
        """
        Returns the data of the storage file as a file-like object.
        The file-like object must be compatible with close_temp_io.
        """
        f = open_temp_io(size_hint)
        self._bucket().download_fileobj(str(self.base_path / storage_filename), f)
        return f
    
    def rename(self, from_storage_filename, to_storage_filename):
        """
        Renames from a storage filename to another name.
        """
        from_source = {
            'Bucket': self.s3_bucket,
            'Key': str(self.base_path / from_storage_filename),
            }
        self._bucket().copy(from_source, str(self.base_path / to_storage_filename))
        self._bucket().meta.client.delete_object(**from_source)
    
    def remove(self, storage_filename):
        """
        Removes a file from the storage.
        """
        self._bucket().meta.client.delete_object(**{
            'Bucket': self.s3_bucket,
            'Key': str(self.base_path / storage_filename),
            })
    
    def _bucket(self):
        """
        Internally used to return the boto3 bucket.
        """
        args = dict(self.s3_args)
        config = Config(
            retries={
                'total_max_attempts': 10,
                'mode': 'adaptive',
                },
            signature_version=args.pop('signature_version'))
        s3 = boto3.resource('s3', **dict(args, config=config))
        return s3.Bucket(self.s3_bucket)
    
    def _list(self, extension=None):
        """
        Internally used by list and list_iter.
        """
        extension = '.' + extension if extension else None
        
        if str(self.base_path) != '.':
            it = self._bucket().objects.filter(Prefix=str(self.base_path) + '/')
        else:
            it = self._bucket().objects.all()
        
        for obj in it:
            if obj.key.endswith('/'):
                continue # ignore folders
            p = PurePath(obj.key).relative_to(self.base_path)
            if extension is None or p.suffix == extension:
                yield str(p), obj

STORAGES.append(S3Storage)

CONFIG_ALL.extend(
    reduce(operator.add, [['src.%s' % a for a in s.ARGS] for s in STORAGES]) +
    reduce(operator.add, [['dest.%s' % a for a in s.ARGS] for s in STORAGES]) +
    reduce(operator.add, [['restore.%s' % a for a in s.ARGS] for s in STORAGES])
    )


#
# Main functions
#
def backup_object(index, config, src_storage, dest_storage, original_state):
    """
    Downloads an object from the source storage, compresses and then encrypts 
    and stores it on the destination storage.
    """
    log('[{0}] Backing up {1}...'.format(index + 1, original_state.storage_filename))
    
    # download/read the original file from the source storage
    original_io = src_storage.read(original_state.storage_filename, original_state.size)
    
    # determine the size and md5 of the data before encrypted
    original_md5, original_size = md5_hash_and_size(original_io)
    
    assert original_state.size == original_size, \
        'Download failed for [%s]. Size mismatch. Expected %s, got %s!' % (
            original_state.storage_filename, original_state.size, original_size)
    
    # compress the file using lzma (xz) or gzip
    if as_bool(config.get('compress', True)):
        compressed_io = open_temp_io(original_size)
        compress(original_io, compressed_io, 
            lzma_level=int(config.get('lzma_level') or 6), 
            gzip_level=int(config.get('gzip_level') or 6))
        close_temp_io(original_io)
    else:
        compressed_io = original_io
    
    # encrypt the data using aes-256-gcm
    if as_bool(config.get('encrypt', True)):
        encrypted_io = open_temp_io(io_size(compressed_io))
        encrypt(compressed_io, encrypted_io, 
            password=config.get('encryption_password'), key=config.get('encryption_key'), 
            salt=config.get('encryption_salt'), encryption_type=config.get('encryption_type'))
        close_temp_io(compressed_io)
    else:
        encrypted_io = compressed_io
    
    # write the encrypted file to the storage
    encrypted_filename = encrypted_file_state_to_encrypted_filename(config, 
        original_filename=original_state.storage_filename,
        last_modified=original_state.last_modified, 
        original_size=original_state.size, 
        original_md5=original_md5,
        deleted_date=0)
    dest_storage.write(encrypted_filename, encrypted_io)
    close_temp_io(encrypted_io)
    
    
def remove_object(index, dest_storage, storage_filename, msg):
    """
    Removes an object from the destination storage.
    """
    log('[{0}] {1}'.format(index + 1, msg))
    dest_storage.remove(storage_filename)
    
    
def rename_object(index, dest_storage, from_storage_filename, to_storage_filename, msg):
    """
    Renames an object on the destination storage.
    """
    log('[{0}] {1}'.format(index + 1, msg))
    dest_storage.rename(from_storage_filename, to_storage_filename)


def do_backup(config, src_storage, dest_storage):
    """
    Performs a backup to the storage.
    """
    with Pool(int(config.get('backup_processes') or 4)) as pool:
        processes = []
        
        # load all files on the storage and their state
        log('Listing files on destination storage...')
        
        dest_storage_files = {}
        for s in (encrypted_filename_to_encrypted_file_state(config, f) 
                for f in dest_storage.list(extension=ENCRYPTED_EXTENSION)):
            dest_storage_files.setdefault(s.original_filename, []).append(s)
        
        # handle any conflicts (unlikely) which could occur when:
        # - the storage has a deleted version, plus an undeleted version or
        # - multiple deleted versions
        # we always resolve by keeping the undeleted version or the latest deleted version
        for original_filename, s_list in dest_storage_files.items():
            if len(s_list) > 1:
                for encrypted_state in sorted(s_list, 
                        key=lambda s: s.deleted_date or sys.maxsize, reverse=True)[1:]:
                    msg = 'Fixing conflict by deleting {0} ({1} bytes, modified {2}, deleted {3})...'.format(
                        encrypted_state.original_filename, encrypted_state.original_size, 
                        datetime.utcfromtimestamp(encrypted_state.last_modified), 
                        encrypted_state.deleted_date)
                    # as these shouldn't occur, perform synchronously to ensure 
                    # completion before the backup starts
                    remove_object(-2, dest_storage, encrypted_state.encrypted_filename, msg)
            
            dest_storage_files[original_filename] = s_list[0]
        
        src_storage_files = set()
        ignore_regexes = [re.compile(r) for r in config.get('ignore_regex', [])]
        
        log('Listing files on source storage and queuing downloads...')
        
        for i, original_state in enumerate(src_storage.list_iter()):
            if any(r.match(original_state.storage_filename) for r in ignore_regexes):
                continue # the user has requested to ignore
            if original_state.storage_filename in src_storage_files:
                continue # in case the storage lists the file twice (unlikely)
            
            src_storage_files.add(original_state.storage_filename)
            encrypted_state = dest_storage_files.get(original_state.storage_filename)
            
            # if the file has never been downloaded, then queue for downloading
            # or if the file has changed size or been modified, then queue for downloading
            if (encrypted_state is None or 
                    encrypted_state.original_size != original_state.size or 
                    encrypted_state.last_modified != original_state.last_modified):
                processes.append(pool.apply_async(backup_object,
                    [i, config, src_storage, dest_storage, original_state]))
                
                # remove any old version of the file
                if encrypted_state is not None:
                    msg = 'Deleting old {0} ({1} bytes, modified {2}, deleted {3})...'.format(
                        original_state.storage_filename, encrypted_state.original_size, 
                        datetime.utcfromtimestamp(encrypted_state.last_modified), 
                        encrypted_state.deleted_date)
                    processes.append(pool.apply_async(remove_object,
                        [i, dest_storage, encrypted_state.encrypted_filename, msg]))
            
            # if the file has been deleted, then mark it as not deleted
            elif encrypted_state.deleted_date:
                msg = 'Marking as undeleted {0}...'.format(original_state.storage_filename)
                processes.append(pool.apply_async(rename_object,
                    [i, dest_storage, encrypted_state.encrypted_filename, 
                        encrypted_file_state_to_encrypted_filename(config, encrypted_state, 
                            deleted_date=0), msg]))
        
        # mark all missing files that exist on the storage as deleted
        today = date.today()
        today_int = date_to_int(today)
        deleted_keep_days = config.get('deleted_keep_days')
        
        for original_filename in set(dest_storage_files) - src_storage_files:
            encrypted_state = dest_storage_files[original_filename]
            
            if encrypted_state.deleted_date:
                # previously deleted, so check whether its expired and is to be permanently deleted
                if deleted_keep_days is not None:
                    days = (today - int_to_date(encrypted_state.deleted_date)).days
                    if days > int(deleted_keep_days):
                        msg = 'Permanently deleting {0}...'.format(original_filename)
                        processes.append(pool.apply_async(remove_object,
                            [i, dest_storage, encrypted_state.encrypted_filename, msg]))
            else:
                msg = 'Marking as deleted {0}...'.format(original_filename)
                processes.append(pool.apply_async(rename_object,
                    [i, dest_storage, encrypted_state.encrypted_filename,
                        encrypted_file_state_to_encrypted_filename(config, encrypted_state, 
                            deleted_date=today_int), msg]))
        
        # wait for all processes to finish and raise any exceptions they raise
        log('Listing source complete! Waiting for backups to finish...')
        for process in processes:
            process.get() # re-raises any exceptions


def restore_object(index, config, dest_storage, encrypted_state, encrypted_size, 
        restore_storage=None, verify=False):
    """
    Restores an object from the destination storage to the restore storage.
    """
    log('[{0}] Restoring {1}...'.format(index + 1, encrypted_state.original_filename))
    
    # read the encrypted file
    encrypted_io = dest_storage.read(encrypted_state.encrypted_filename, encrypted_size)
    
    # decrypt the data using aes or cha
    if as_bool(config.get('encrypt', True)):
        compressed_io = open_temp_io(io_size(encrypted_io))
        decrypt(encrypted_io, compressed_io, 
            password=config.get('encryption_password'), key=config.get('encryption_key'), 
            salt=config.get('encryption_salt'), encryption_type=config.get('encryption_type'))
        close_temp_io(encrypted_io)
    else:
        compressed_io = encrypted_io
    
    # decompress the file using lzma (xz) or gzip
    if as_bool(config.get('compress', True)):
        original_io = open_temp_io(io_size(compressed_io))
        decompress(compressed_io, original_io)
        close_temp_io(compressed_io)
    else:
        original_io = compressed_io
    
    # verify the contents
    error = None
    original_md5, original_size = md5_hash_and_size(original_io)
    
    if encrypted_state.original_size != original_size:
        error = 'Restore failed for [%s]. Size mismatch. Expected %s, got %s!' % (
            encrypted_state.original_filename, encrypted_state.original_size, original_size)
        
    elif encrypted_state.original_md5 != original_md5:
        error = 'Restore failed for [%s]. MD5 mismatch. Expected %s, got %s!' % (
            encrypted_state.original_filename, encrypted_state.original_md5, original_md5)
    
    if error:
        if verify:
            log('[{0}] {1}'.format(index + 1, error), file=sys.stderr)
            return
        else:
            raise ValueError(error) # backup is corrupt, so bail
    
    if verify:
        log('[{0}] OK'.format(index + 1))
    else:
        # save the file to it's destination
        restore_storage.write(encrypted_state.original_filename, original_io)
    
    close_temp_io(original_io)


def do_restore(config, dest_storage, restore_storage=None, restore_only=None, restore_deleted=False, 
        verify=False):
    """
    Performs a restore from the storage to a directory, optionally including deleted files.
    """
    with Pool(int(config.get('restore_processes') or 4)) as pool:
        processes = []
        
        log('Listing files on destination storage...')
        
        for i, storage_state in enumerate(dest_storage.list_iter(extension=ENCRYPTED_EXTENSION)):
            encrypted_state = encrypted_filename_to_encrypted_file_state(config, 
                storage_state.storage_filename)
            
            if not verify and restore_only and encrypted_state.original_filename not in restore_only:
                continue # only restore selected files
            if not verify and encrypted_state.deleted_date and not restore_deleted:
                continue # skip deleted (except when verifying)
            
            processes.append(pool.apply_async(restore_object, [i, config, dest_storage, 
                encrypted_state, storage_state.size, restore_storage, verify]))            
        
        # wait for all processes to finish and raise any exceptions they raise
        log('Listing complete! Waiting for restoration to finish...')
        for process in processes:
            process.get() # re-raises any exceptions        


#
# Utility functions
#
def log(msg, file=None):
    """
    Log's a message.
    """
    print('[%s] %s' % (datetime.now().isoformat(timespec='seconds'), msg), file=file, flush=True)


def as_bool(v):
    """
    Returns a value as a boolean value. Handles strings that represent boolean values.
    """
    if isinstance(v, str):
        return v.lower() not in ('no', 'false', 'n', 'f', '0', '')
    return bool(v)


def encrypted_filename_to_encrypted_file_state(config, encrypted_filename):
    """
    Splits the filename of an encrypted file into an EncryptedFileState.
    The state of an encrypted file is stored within it's filename.
    """
    encrypted_basename, extension = encrypted_filename.rsplit('.', 1)
    assert extension == ENCRYPTED_EXTENSION
    
    if as_bool(config.get('encrypt_filenames', False)):
        try:
            encrypted_basename = decrypt_str(b36decode(encrypted_basename), 
                password=config.get('encryption_password'), key=config.get('encryption_key'), 
                salt=config.get('encryption_salt'), encryption_type=config.get('encryption_type'))
        except:
            pass
    
    original_filename, last_modified, original_size, original_md5, deleted_date = \
        encrypted_basename.rsplit('.', 4)
    
    return EncryptedFileState(encrypted_filename=encrypted_filename,
        original_filename=original_filename,
        last_modified=b36decode_int(last_modified), 
        original_size=b36decode_int(original_size), 
        original_md5=b36decode_int(original_md5),
        deleted_date=b36decode_int(deleted_date))


def encrypted_file_state_to_encrypted_filename(config, encrypted_state=None, **kwargs):
    """
    Returns the filename that should be used to store the encrypted file on the storage.
    """
    if encrypted_state and kwargs:
        encrypted_state = EncryptedFileState(**dict(encrypted_state._asdict(), **kwargs))
    elif kwargs:
        encrypted_state = EncryptedFileState(**kwargs)
    
    encrypted_basename = '.'.join([
        encrypted_state.original_filename,
        b36encode_int(encrypted_state.last_modified),
        b36encode_int(encrypted_state.original_size),
        b36encode_int(encrypted_state.original_md5),
        b36encode_int(encrypted_state.deleted_date),
        ])
    
    if as_bool(config.get('encrypt_filenames', False)):
        encrypted_basename = b36encode(encrypt_str(encrypted_basename, 
            password=config.get('encryption_password'), key=config.get('encryption_key'), 
            salt=config.get('encryption_salt'), encryption_type=config.get('encryption_type')))
    
    return '%s.%s' % (encrypted_basename, ENCRYPTED_EXTENSION)


def read_chunks(f):
    """
    Reads in chunks of a file and yields the chunk.
    """
    while True:
        data = f.read(CHUNK_SIZE)
        if not data:
            break
        yield data


def io_size(f):
    """
    Returns the file size for a given file-like object.
    """
    f.seek(0, SEEK_END)
    return f.tell()


def open_temp_io(size_hint):
    """
    Opens a temporary file-like object depending on the size of the data to be stored.
    """
    if size_hint <= IN_MEMORY_MAX_SIZE:
        return BytesIO()
    else:
        return NamedTemporaryFile(delete=False)


def close_temp_io(f):
    """
    Closes a temporary file-like object opened using open_temp_io.
    """
    f.close()
    if isinstance(f, _TemporaryFileWrapper) and not f.delete and os.path.exists(f.name):
        os.remove(f.name)


def md5_hash_and_size(f):
    """
    Calculates the MD5 hash of a file-like object (as an integer), and the size of the file in bytes.
    """
    f.seek(0)
    
    h = hashlib.md5()
    size = 0
    for chunk in read_chunks(f):
        h.update(chunk)
        size += len(chunk)
    
    return int(h.hexdigest(), 16), size


def compress(from_io, to_io, lzma_level=6, gzip_level=6):
    """
    Compresses a file-like object into another file-like object using LZMA (XZ) if the file
    is small, and GZIP if the file is greater than LZMA_MAX_SIZE.
    """
    size = io_size(from_io)
    
    from_io.seek(0)
    to_io.seek(0)
    
    if size <= LZMA_MAX_SIZE:
        with lzma.LZMAFile(to_io, mode='wb', preset=lzma_level) as f:
            for chunk in read_chunks(from_io):
                f.write(chunk)
    else:
        with gzip.GzipFile(fileobj=to_io, mode='wb', compresslevel=gzip_level) as f:
            for chunk in read_chunks(from_io):
                f.write(chunk)


def decompress(from_io, to_io):
    """
    Decompresses a file-like object into another file-like object using LZMA or GZIP.
    """
    from_io.seek(0)
    magic_number = from_io.read(2)
    from_io.seek(0)
    to_io.seek(0)
    
    if magic_number == b'\x1f\x8b':
        with gzip.GzipFile(fileobj=from_io, mode='rb') as f:
            for chunk in read_chunks(f):
                to_io.write(chunk)
    else:
        with lzma.LZMAFile(from_io, mode='rb') as f:
            for chunk in read_chunks(f):
                to_io.write(chunk)


def pbkdf2_key(encryption_password, salt):
    """
    Generates an encryption key from a password using the PBKDF2-SHA512 kdf.
    """
    return PBKDF2(encryption_password, salt, 32, count=100000, hmac_hash_module=SHA512)


def argon2_key(encryption_password, salt):
    """
    Generates an encryption key from a password using the Argon2id KDF.
    """
    return argon2.low_level.hash_secret_raw(encryption_password.encode('utf-8'), salt, 
        time_cost=RFC_9106_LOW_MEMORY.time_cost, memory_cost=RFC_9106_LOW_MEMORY.memory_cost, 
        parallelism=RFC_9106_LOW_MEMORY.parallelism, hash_len=32, type=argon2.low_level.Type.ID)


def encrypt_str(s, *args, **kwargs):
    """
    Like encrypt() but encrypts a string and returns the bytes.
    """
    from_io = BytesIO(s.encode('utf-8'))
    to_io = BytesIO()
    encrypt(from_io, to_io, *args, **kwargs)
    return to_io.getvalue()


def encrypt(from_io, to_io, password=None, key=None, salt=None, encryption_type=None):
    """
    Encrypts a file-like object into another file-like object.
    """
    encryption_type = encryption_type or DEFAULT_ENCRYPTION_TYPE
    
    from_io.seek(0)
    to_io.seek(0)
    
    if key is None:
        salt = get_random_bytes(16)
        if encryption_type == 'aes':
            key = pbkdf2_key(password, salt)
        elif encryption_type == 'cha':
            key = argon2_key(password, salt)
    
    if encryption_type == 'aes':
        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce)
    elif encryption_type == 'cha':
        nonce = get_random_bytes(24) # XChaCha20-Poly1305 is 24
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)          
    
    to_io.write(salt)
    to_io.write(nonce)
    to_io.seek(16, SEEK_CUR) # leave 16 bytes for the digest
    
    for chunk in read_chunks(from_io):
        to_io.write(cipher.encrypt(chunk))
    
    to_io.seek(len(salt) + len(nonce))
    to_io.write(cipher.digest())


def decrypt_str(b, *args, **kwargs):
    """
    Like decrypt() but decrypts bytes and returns the string.
    """
    from_io = BytesIO(b)
    to_io = BytesIO()
    decrypt(from_io, to_io, *args, **kwargs)
    return to_io.getvalue().decode('utf-8')


def decrypt(from_io, to_io, password=None, key=None, salt=None, encryption_type=None):
    """
    Decrypts a file-like object into another file-like object.
    """
    encryption_type = encryption_type or DEFAULT_ENCRYPTION_TYPE
    
    from_io.seek(0)
    to_io.seek(0)
    
    salt_ = from_io.read(16)
    if key is None or salt_ != salt:
        if encryption_type == 'aes':
            key = pbkdf2_key(password, salt_)
        elif encryption_type == 'cha':
            key = argon2_key(password, salt_)    
    
    if encryption_type == 'aes':
        cipher = AES.new(key, AES.MODE_GCM, from_io.read(16))
    elif encryption_type == 'cha':
        cipher = ChaCha20_Poly1305.new(key=key, nonce=from_io.read(24)) # XChaCha20-Poly130 is 24  
        
    digest = from_io.read(16)
    
    for chunk in read_chunks(from_io):
        to_io.write(cipher.decrypt(chunk))
    
    cipher.verify(digest)


def date_to_int(d):
    """
    Represents a date object as an integer, or 0 if None.
    """
    if d is None:
        return 0
    return int(d.strftime('%Y%m%d'))


def int_to_date(d):
    """
    Converts an integer representation of a date to a date object or None.
    """
    if d == 0:
        return None
    return datetime.strptime(str(d), '%Y%m%d').date()


def b36encode(b):
    """
    Encodes bytes as a lowercase base36 string.
    """
    return base36.b36encode(b).decode('ascii').lower()


def b36encode_int(i):
    """
    Encodes an integer as a lowercase base36 string.
    """
    h = '{:x}'.format(i)
    if len(h) % 2:
        h = '0' + h # ensure pairs
    return b36encode(bytes.fromhex(h))


def b36decode(s):
    """
    Decodes a lowercase base36 string to bytes.
    """
    return base36.b36decode(s.upper().encode('ascii'))


def b36decode_int(s):
    """
    Decodes a lowercase base36 string to an integer.
    """
    return int(b36decode(s).hex(), 16)


#
# Main
#
def main():
    """
    Runs the backup, verify or restore.
    """
    log('encrypted_s3_backup started.')
    
    # parse the command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.json',
        help='Specify the path to the config file.')
    parser.add_argument('--verify', action='store_true',
        help='Verifies the integrity of a backup by decrypting and verifying hashes.')
    parser.add_argument('--restore', action='store_true',
        help='Perform a restore instead of a backup.')
    parser.add_argument('--restore-only', action='append',
        help='Specifies file(s) to only restore. Other files will be ignored.')
    parser.add_argument('--restore-deleted', action='store_true',
        help='Restore deleted files during the restore. Not enabled by default.')
    args = parser.parse_args()
    
    # load the configuration via environment variables, if any are set
    config = {}
    env_used = False
    
    for arg in CONFIG_ALL:
        env_name = arg.upper().replace('.', '_')
        
        if os.environ.get(env_name):
            env_used = True
            
            if '.' in arg:
                parent, arg = arg.split('.', 1)
                obj = config.setdefault(parent, {})
            else:
                obj = config
            
            obj[arg] = os.environ[env_name]
    
    # if no environment variables were found, then load via the json config file
    if not env_used:  
        with open(args.config, 'rb') as f:
            config = json.load(f)
    
    # generate the encryption key upfront if a fixed salt is used
    if config.get('encryption_salt'):
        config['encryption_salt'] = bytes.fromhex(config['encryption_salt'])
        
        encryption_type = config.get('encryption_type') or DEFAULT_ENCRYPTION_TYPE
        if encryption_type == 'aes':
            config['encryption_key'] = pbkdf2_key(config['encryption_password'], 
                config['encryption_salt'])
        elif encryption_type == 'cha':
            config['encryption_key'] = argon2_key(config['encryption_password'], 
                config['encryption_salt'])
    
    # load all storages
    if not config.get('restore'):
        config.setdefault('restore', {})['local_path'] = str(Path(gettempdir()) / 
            'encrypted_s3_backup_restore')
    
    for storage_class in STORAGES:
        if any(a in config['src'] for a in storage_class.ARGS):
            src_storage = storage_class(**config['src'])
        if any(a in config['dest'] for a in storage_class.ARGS):
            dest_storage = storage_class(**config['dest'])
        if any(a in config['restore'] for a in storage_class.ARGS):
            restore_storage = storage_class(**config['restore'])
    
    dest_storage.init()
    
    # perform the backup or restore
    if args.verify:
        do_restore(config, dest_storage, verify=True)
    elif args.restore:
        restore_storage.init()
        do_restore(config, dest_storage, restore_storage=restore_storage, 
            restore_only=args.restore_only, restore_deleted=args.restore_deleted)
    else:
        src_storage.init()
        do_backup(config, src_storage, dest_storage)
    
    log('Done!')


if __name__ == '__main__':
    sys.exit(main())