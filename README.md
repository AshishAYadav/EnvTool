# Env-Tool

Env-Tool is a command line interface program that allows you to securely manage environment variables. The tool provides the ability to encrypt environment variables in JSON format and output a dotenv-compatible `.env` file.

## Features

- Encrypt environment variables in JSON format to a dotenv-compatible `.env` file.
- Decrypt a `.env` file back to the original JSON format.
- Generate RSA public and private keys for use in the encryption and decryption process.

## Requirements

- OpenSSL installation is required to generate RSA public and private keys.

## Usage

Env-Tool provides the following commands:

```
env-tool encrypt[--encrypt] input-path[env.json] public-key-path output-path[.env]

env-tool decrypt[--decrypt] input-path[.env] private-key-path output-path[env.json]

env-tool keygen[--keygen] output-dir[.keys]
```


### Encrypt

To generate an encrypted `.env` file from a `env.json` file:

```
env-tool encrypt[--encrypt] ./env.json ./.keys/rsa_public.pem .env
```


### Decrypt

To generate a decrypted `env.json` file from a `.env` file:

```
env-tool decrypt[--decrypt] ./.env ./.keys/rsa_private.pem env.json
```


### Keygen

To generate RSA public and private keys:

```
env-tool keygen[--keygen] .keys
```


## RSA Public and Private Key Generation

The RSA public and private keys can be generated using the following OpenSSL commands:

```
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```


## Binary Generation

To generate the `env-tool` binary, run the following command:

```
npm run build
```

This will generate the binary in the `builds` folder. The binary can be used without a Node.js runtime.

## RSA Public and Private Key Generation

The RSA public and private keys can be generated using the following OpenSSL commands:


## Security

It is important to store the private key in a secure location and keep it private. The private key is required to decrypt the environment variables stored in the `.env` file.

## Contributing

We welcome contributions to Env-Tool! If you have an idea for a feature or bug fix, feel free to submit a pull request.

## License

Env-Tool is licensed under the [GNU General Public License 3.0](LICENSE).
