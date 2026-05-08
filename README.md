![mytoken logo](https://raw.githubusercontent.com/oidc-mytoken/server/master/mytoken.png)

[![License](https://img.shields.io/github/license/oidc-mytoken/client.svg)](https://github.com/oidc-mytoken/client/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/oidc-mytoken/client)
[![Go Report](https://goreportcard.com/badge/github.com/oidc-mytoken/client)](https://goreportcard.com/report/github.com/oidc-mytoken/client)
[![DeepSource](https://deepsource.io/gh/oidc-mytoken/client.svg/?label=active+issues&show_trend=true)](https://deepsource.io/gh/oidc-mytoken/client/?ref=repository-badge)
[![Release date](https://img.shields.io/github/release-date/oidc-mytoken/client.svg)](https://github.com/oidc-mytoken/client/releases/latest)
[![Release version](https://img.shields.io/github/release/oidc-mytoken/client.svg)](https://github.com/oidc-mytoken/client/releases/latest)

<!-- [![Code size](https://img.shields.io/github/languages/code-size/oidc-mytoken/client.svg)](https://github.com/oidc-mytoken/client/tree/master) -->

# mytoken

[`Mytoken`](https://github.com/oidc-mytoken/server) is a web service to obtain OpenID Connect Access Tokens in an easy 
but secure way for extended periods of time and across multiple devices. In particular, `mytoken` was developed to
provide OIDC Access Tokens to long-running compute jobs.

Access Tokens can be obtained via so-called **`mytokens`**: A new token type that can be easily used as a Bearer token from
any device. These `mytokens` can be restricted according to the particular use case to only allow the needed privileges.

`Mytoken` focuses on integration with the command line through this command line client <!-- and [oidc-agent]
(https://github.com/indigo-dc/oidc-agent) --> but also offers a web interface.
A demo instance of the server and webinterface is available at
[https://mytoken.data.kit.edu/](https://mytoken.data.kit.edu/).

Documentation is available at [https://docs.mytok.eu/](https://docs.mytok.eu/).

A go library for interacting with the mytoken server can be found at
[https://github.com/oidc-mytoken/lib](https://github.com/oidc-mytoken/lib).

# Quickstart

## Installation

Packaged versions are available from http://repo.data.kit.edu

The latest version can also be installed via `go`:

```bash
go install github.com/oidc-mytoken/client/cmd/mytoken@latest
```

## Basic Usage

### Obtain a mytoken

Get a mytoken:

```bash
mytoken MT --url <mytoken_url> -i <oidc_issuer_url> -o <path_to_MT>
```

The mytoken will be stored in `<path_to_MT>`.

### Get an Access Token

Use your mytoken to obtain an OIDC access token:

```bash
mytoken AT --MT-file <path_to_MT>
```

## Using Mytokens

Mytokens can be provided in several ways:

- **File** (default): Stored in `~/.mytoken/default/mytoken`
- **Environment variable**: `mytoken AT --MT-env MYTOKEN_VAR`
- **From file**: `mytoken AT --MT-file /path/to/token`
- **Interactive prompt**: `mytoken AT --MT-prompt`
- **Direct**: `mytoken AT --MT <token>` (less secure)
