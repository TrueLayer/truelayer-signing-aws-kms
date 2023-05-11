# Truelayer Signing with AWS KMS

This repository contains some example code for generating a `TL-Signature` for a request using AWS KMS, in Typescript/Node.


### Prerequisities

- A `ECC_NIST_P521` `SIGN_VERIFY` key provisioned in KMS
- IAM credentials (see [here](https://docs.aws.amazon.com/sdkref/latest/guide/access-iam-users.html)) provisions and given explicit access as a key user in the key policy of the provisioned key
- The following environment variables (note can be put in a `.env` file in the root of this repo):
  - `AWS_ACCESS_KEY_ID`: The access key ID for the IAM credentials
  - `AWS_SECRET_ACCESS_KEY`: The access key for the IAM credentials
  - `AWS_REGION`: The AWS region the signing key was provisioned in
  - `AWS_KMS_SIGNING_KEY_ID`: The AWS KMS Key ID of the provisioned signing key

## Running

First restore packages using `npm ci`, then simply: 

```bash
npm start
```