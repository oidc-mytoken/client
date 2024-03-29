![mytoken logo](https://raw.githubusercontent.com/oidc-mytoken/server/master/mytoken.png)

[![License](https://img.shields.io/github/license/oidc-mytoken/client.svg)](https://github.com/oidc-mytoken/client/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/oidc-mytoken/client)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/oidc-mytoken/client/Go)
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

Documentation is available at [https://mytoken-docs.data.kit.edu/](https://mytoken-docs.data.kit.edu/).

A go library for interacting with the mytoken server can be found at
[https://github.com/oidc-mytoken/lib](https://github.com/oidc-mytoken/lib).
