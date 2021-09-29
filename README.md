# Hub88-Examples
Examples of code to interact with Hub88 API

## Signature generation and validation
All examples imply that you have already generated ssl-rsa key-pair with such command:
```bash
openssl genrsa -out private.pem 2048
```
and extracted public key:
```bash
openssl rsa -in private.pem -pubout > public.pub
```
### General workflow
**Signing:**

Prerequisite:
1. generate private and public key.
2. send public key to Hub88 representative

Process:
1. sign request body with your private key
2. encode signature in base64
3. put result of step 2 into header X-Hub88-Signature
4. send request

**Validation of signature:**

Prerequisite: receive and save Hub88 public key

Process:
1. receive request
2. get value of X-Hub88-Signature header
3. decode it from base64
4. check that result of step 3 is valid for combination of this request body and Hub88 public key

### Examples
We have few [code examples](/examples) for generating of signature and it's validation. Also [`priv`](/priv) folder contains demo pair of private and public keys.
* Elixir
* NodeJS
* Java
* PHP
* .NET
* Bash
* Python

In file [signatures.csv](signatures.csv) you can find examples of data and corresponding signature(signed with private key from [priv](/priv) folder). Try to get same signatures and validate these signatures with [public key](/priv/public.pem)
