docker tag encrypted_s3_backup:$1 ghcr.io/masterapps-au/encrypted_s3_backup:$1
docker push ghcr.io/masterapps-au/encrypted_s3_backup:$1
docker tag encrypted_s3_backup:$1 ghcr.io/masterapps-au/encrypted_s3_backup:latest
docker push ghcr.io/masterapps-au/encrypted_s3_backup:latest
