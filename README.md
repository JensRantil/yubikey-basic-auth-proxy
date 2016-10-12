[![Build Status](https://secure.travis-ci.org/JensRantil/yubikey-basic-auth-proxy.png?branch=master)](http://travis-ci.org/JensRantil/yubikey-basic-auth-proxy) [![Go Report Card](https://goreportcard.com/badge/github.com/JensRantil/yubikey-basic-auth-proxy)](https://goreportcard.com/report/github.com/JensRantil/yubikey-basic-auth-proxy) [![GoDoc](https://godoc.org/github.com/JensRantil/yubikey-basic-auth-proxy?status.svg)](https://godoc.org/github.com/JensRantil/yubikey-basic-auth-proxy)

# Yubikey Basic Auth HTTP(S) Proxy.

Reverse HTTP(S) Proxy that adds a layer of Basic Auth that does Yubikey authentication.
To allow proxying through the application, a user must validate correctly using
a username+password+valid Yubikey OTP.

```
------------            ----------------------------                 ------------
|          | (HTTP/TLS) |                          |    (HTTP/TLS)   |          |
| Internet |   <--->    | yubikey-basic-auth-proxy |      <--->      | Upstream |
|          |            |     (authentication)     | (authenticated) |          |
------------            ----------------------------                 ------------
```

## Features

 * Support for non-encrypted HTTP as well as TLS.
 * Simple command line interface to configure the ACL, which is stored on disk
   in a single JSON file.
 * Strong password hashing using
   [scrypt](https://en.wikipedia.org/wiki/Scrypt).

## Usage

```bash
$ ./yubikey-basic-auth-proxy --help
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

  credentials add <username> <yubikey> [<password>]
    Add a credentials.

  credentials list
    List the credentials.

  credentials remove <username> [<yubikey>]
    Delete a credentials.
```
Execute `./yubikey-basic-auth-proxy COMMAND --help` for command specific flags.

## Current limitations

 * Auth cookie can't be used upstream. See
   [#1](https://github.com/JensRantil/yubikey-basic-auth-proxy/issues/1).
 * HTTP Basic Auth can't be used upstream. See
   [#2](https://github.com/JensRantil/yubikey-basic-auth-proxy/issues/2).
