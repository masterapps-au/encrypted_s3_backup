# encrypted_s3_backup

encrypted_s3_backup is a fast multi-threaded backup script that backs up files in a 
compressed (XZ/GZIP) and encrypted format (AES-256-GCM or XChaCha20-Poly1305). 
Files can be backed up to or from S3 or local storage. It requires Python 3.5+.

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

`mypicture.jpg.ptcjvk.emz.8ji0wkvrgyrnqkqsrdirborvq.0.enc`


## How to Run Locally

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


## How to Automate Backups via Docker

The included docker image contains cron and allows you to schedule encrypted_s3_backup to be run 
periodically.

How often cron runs is controlled via the `CRONTAB` environment variable. The default is `0 * * * *`,
which means it will run on the hour, every hour.

A minimal example which backs up the a local folder `/path/to/backup` to Amazon S3:

`docker run -d --name encrypted_s3_backup
  -e SRC_LOCAL_PATH=/data
  -e DEST_AWS_ACCESS_KEY_ID=my_key -e DEST_AWS_SECRET_ACCESS_KEY=my_secret -e DEST_S3_BUCKET=my-bucket
  -e ENCRYPTION_PASSWORD=my-encryption-password
  -v /path/to/backup:/data
  ghcr.io/masterapps-au/encrypted_s3_backup`

Alternatively you can use the docker container to run the script directly to do a backup, 
restore or verify. For example:

`docker run -it --rm
  -e SRC_LOCAL_PATH=/data
  -e DEST_AWS_ACCESS_KEY_ID=my_key -e DEST_AWS_SECRET_ACCESS_KEY=my_secret -e DEST_S3_BUCKET=my-bucket
  -e ENCRYPTION_PASSWORD=my-encryption-password
  -v /path/to/backup:/data
  ghcr.io/masterapps-au/encrypted_s3_backup
  /encrypted_s3_backup.py --verify`

Note: It is suggested you use the "Config Environment Variables" like in the examples above, to 
avoid mounting a config.json file.


## Config File Format

The structure of the config.json file. Alternatively you can set configuration values via environment
variables. See "Config Environment Variables" below.


### Storages

`src`, `dest`, and `restore` keys define a storage to use as the source, the destination and 
where to restore to, respectively. Each storage can be either a LocalStorage, or S3Storage.

`restore` is special in that it defaults to a `local_path` of `$TMPDIR/encrypted_s3_backup_restore` 
if no `restore` is provided.

**LocalStorage**

`local_path` - Required. The local path to read or write files to.

**S3Storage**

`aws_access_key_id` - Required. The access key used to access S3, or an S3-like storage.

`aws_secret_access_key` - Required. The secret key used to access S3, or an S3-like storage.

`s3_bucket` - Required. The bucket to read from or write files to.

`base_path` - Optional. Defaults to /. A path within the bucket to read from or write files to.

`endpoint_url` - Optional. Default is null. A different S3 endpoint to use. Allows specifying other 
S3-like providers.

`signature_version` - Optional. Default is null. Specify a specific S3 signature method to use.

`region_name` - Optional. Default is null. Specify a specific S3 region to use.


### Other Settings

`encryption_password` - Required. The password to use to encrypt the destination (backup) files.

`encryption_salt` - Recommended. Default is null. Generate using the generate_salt.py command. 
Enables a single encryption key to be used across all files (and filenames if encrypt_filenames is 
enabled). This greatly speeds up initial backups, restores and filename encryption because key 
generation (KDF) is only run once, instead of every file or filename. This comes with a slight 
reduction in security.

`encrypt_filenames` - Optional. Default false. Encrypt filenames to ensure privacy. Recommended to use
encryption_salt if you enable this feature, otherwise decryption of filenames will take a very long 
time if you have a large number of files.

`backup_processes` - Optional. Default 5. The number of processes to use to backup files in parallel. 

`restore_processes` - Optional. Default 8. The number of processes to use to restore files in parallel. 

`deleted_keep_days` - Optional. Default is null (keep forever). The number of days until deleted 
files are permanently deleted from the destination (backup). 

`ignore_regex` - Optional. Default is []. A list of regular expressions that can be used to ignore 
files or folders on the source storage.

`lzma_level` - Optional. Default 6. Compression level for LZMA when compressing files <=10MB.  
1 is fastest, 9 is slowest.

`gzip_level` - Optional. Default 6. Compression level for GZIP when compressing files >10MB.
1 is fastest, 9 is slowest.

`compress` - Optional. Default true. Enable or disable compression.

`encrypt` - Optional. Default true. Enable or disable encryption.

`encryption_type` - Optional. Default aes. `aes` for AES-256-GCM with PBKDF2 100,000 iteration KDF. 
`cha` for XChaCha20-Poly1305 with Argon2id KDF.


## Config Environment Variables

Config environment variables map directly to config.json keys, but are instead uppercase and 
separated using _'s. For example, the full list of environment variables are:

`SRC_LOCAL_PATH`
`SRC_AWS_ACCESS_KEY_ID`
`SRC_AWS_SECRET_ACCESS_KEY`
`SRC_S3_BUCKET`
`SRC_BASE_PATH`
`SRC_ENDPOINT_URL`
`SRC_SIGNATURE_VERSION`
`SRC_REGION_NAME`

`DEST_LOCAL_PATH`
`DEST_AWS_ACCESS_KEY_ID`
`DEST_AWS_SECRET_ACCESS_KEY`
`DEST_S3_BUCKET`
`DEST_BASE_PATH`
`DEST_ENDPOINT_URL`
`DEST_SIGNATURE_VERSION`
`DEST_REGION_NAME`

`RESTORE_LOCAL_PATH`
`RESTORE_AWS_ACCESS_KEY_ID`
`RESTORE_AWS_SECRET_ACCESS_KEY`
`RESTORE_S3_BUCKET`
`RESTORE_BASE_PATH`
`RESTORE_ENDPOINT_URL`
`RESTORE_SIGNATURE_VERSION`
`RESTORE_REGION_NAME`

`ENCRYPTION_PASSWORD`
`ENCRYPTION_SALT`
`ENCRYPT_FILENAMES`
`BACKUP_PROCESSES`
`RESTORE_PROCESSES`
`DELETED_KEEP_DAYS`
`IGNORE_REGEX`
`LZMA_LEVEL`
`GZIP_LEVEL`
`COMPRESS`
`ENCRYPT`
`ENCRYPTION_TYPE`


## License

Copyright &copy; 2021 Ryan Butterfield of Master Apps (https://github.com/masterapps-au)

Freely distributable under the terms of the MIT license.
