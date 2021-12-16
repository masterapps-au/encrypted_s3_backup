# encrypted_s3_backup

encrypted_s3_backup is a fast multi-threaded backup script that backs up files in a 
compressed (XZ/GZIP) and encrypted format (AES-256-GCM). Files can be backed up to or from S3 or 
local storage. It requires Python 3.5+.

It has the following features:

- Only changed files are transferred during each run.

- Integrity during restoration is ensured using hashes.

- It uses no state files, lock files, databases, or metadata. Everything is stored in the 
destination (backup) filename. This makes it file system agnostic and ensures writes are atomic.

- Handles files of unlimited size by streaming all large operations to disk (> 100MB).

- Compresses small files (<10MB) using XZ, and large files using GZIP (for speed).

- The format of the destination (backup) filename is:

`[original file name].[last modified date base36].[original file size base36].[original md5 base36].[deleted date (or 0) base36].enc`

eg.

`mypicture.jpg.ptcjvk.emz.8ji0wkvrgyrnqkqsrdirborvq.0.xz-aes`


## How to run

1. Copy one of config.json.example files to config.json.

2. Open the config.json file with your favourite editor and adjust it according to your requirements. 
See the "Config File Format" section below for details.

3. Create a virtual environment (recommended), or use the global environment, and install the 
required third-party packages:

`pip3 install -r requirements.txt`

4. To backup run:

`python3 encrypted_s3_backup.py`

5. To restore run:

`python3 encrypted_s3_backup.py --restore [--restore-deleted]`

You can provide the optional argument of --restore-deleted to restore files that have been deleted.
This protects someone deleting your files and a backup being taken.

6. To verify a backup run:

`python3 encrypted_s3_backup.py --verify 2> errors.log`

Any errors will be output to STDERR, which in the example above writes them to errors.log.


## Config File Format


### Storages

`src`, `dest`, and `restore` keys define a storage to use as the source, the destination and 
where to restore to, respectively. Each storage can be either a LocalStorage, or S3Storage.

**LocalStorage**

`local_path` - Required. The local path to read or write files to.

**S3Storage**

`aws_access_key_id` - Required. The access key used to access S3, or an S3-like storage.

`aws_secret_access_key` - Required. The secret key used to access S3, or an S3-like storage.

`s3_bucket` - Required. The bucket to read from or write files to.

`base_path` - Optional. A path within the bucket to read from or write files to. Defaults to /.

`endpoint_url` - Optional. A different S3 endpoint to use. Allows specifying other S3-like providers.

`signature_version` - Optional. Specify a specific S3 signature method to use.

`region_name` - Optional. Specify a specific S3 region to use.


### Other Settings

`encryption_password` - Required. The password to use to encrypt the destination (backup) files.

`backup_processes` - Optional. The number of processes to use to backup files in parallel. Default 5.

`restore_processes` - Optional. The number of processes to use to restore files in parallel. Default 8.

`deleted_keep_days` - Optional. The number of days until deleted files are permanently deleted from 
the destination (backup). Defaults to null (keep forever).

`ignore_regex` - Optional. A list of regular expressions that can be used to ignore files or 
folders on the source storage.

`lzma_level` - Optional. Compression level for LZMA when compressing files <=10MB. Default 6. 1 is fastest, 9 is slowest.

`gzip_level` - Optional. Compression level for GZIP when compressing files >10MB. Default 6. 1 is fastest, 9 is slowest.


## License

Copyright &copy; 2021 Ryan Butterfield of Master Apps (https://github.com/masterapps-au)

Freely distributable under the terms of the MIT license.
