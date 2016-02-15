[![Build Status](https://secure.travis-ci.org/JensRantil/yubikey-basic-auth-proxy.png?branch=master)](http://travis-ci.org/JensRantil/yubikey-basic-auth-proxy)

# Yubikey Basic Auth HTTP(S) Proxy.

HTTP(S) Proxy that adds a layer of Basic Auth that does Yubikey authentication.
To allow proxying through the application, a user must validate correctly using
a username+password+valid Yubikey OTP.

## Features

 * Support for non-encrypted HTTP as well as TLS.
 * Simple command line interface to configure the ACL, which is stored on disk
   in a single JSON file.
 * Strong password hashing using
   [scrypt](https://en.wikipedia.org/wiki/Scrypt).

## Usage

```bash
./yubikey-basic-auth-proxy --help
usage: yubikey-basic-auth-proxy [<flags>] <command> [<args> ...]

HTTP Proxy that adds a layer of Basic Auth that does Yubikey authentication.

Flags:
  --help            Show context-sensitive help (also try --help-long and --help-man).
  --version         Show application version.
  --credentials-file="credentials.json"
                    The file that stores the credentials.
  --log-level=INFO  Set log level.

Commands:
  help [<command>...]
    Show help.

  serve [<flags>] <upstream> <yubico-api-id> <yubico-api-key>
    Run the proxy.

  credentials init
    Initialize ACL config.

  credentials add <username> <yubikey> [<password>]
    Add a credentials.

  credentials list
    List the credentials.

  credentials remove <username> [<yubikey>]
    Delete a credentials.
```
Execute `./yubikey-basic-auth-proxy COMMAND --help` for command specific flags.

## Current limitations

 * Auth cookie can't be used upstream. See #1.
 * HTTP Basic Auth can't be used upstream. See #2.
