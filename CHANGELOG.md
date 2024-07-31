
## mytoken 0.6.1
- Fail on restrictions error
- Added possibility to revoke tokens by `mom_id`
- Updated lib / api
- Updated dependecies
- Don't fail if defult mytoken server is down but another JWT is used.

## mytoken 0.6.0

### Breaking Changes
- Support for local profiles / templates is dropped. Instead, support for server profiles is added.

### Features
- Added support for server-side profiles / templates

### API
- Adapt to newest api

### Bugfixes
- Fixed the geoip allow and disallow command line options

## mytoken 0.5.2
- Added qr code to oidc flow
- Added application name to request

## mytoken 0.5.1
- bump json patch
- fixed `stdout` printing bug on windows

## mytoken 0.5.0
- Adapt to API
- Drop support for subtoken_capabilities
- Drop support for token management
- Add support for profiles & templates
- Add support for WLCG Bearer token discovery

## mytoken 0.4.2
- adapt to api 0.7

## mytoken 0.4.1
- adapt to api / lib changes

## mytoken 0.4.0
- Adapt to api and server version 0.4.0
- Improve some outputs with tables instead of json
- Add support for token rotation
- Add rename command
- Delete a mytoken from the tokens file on revocation if it is stored there
- Fix command line falgs position with subcommands
- Implement settings / user grants / ssh key list, upload, deletion
- Implement actions through ssh

## mytoken 0.3.0
- Changed cli lib; improved help output formatting

## mytoken 0.2.0
Mytoken 0.2.0 has the following features
- Obtain mytokens
    - Through authorization code flow
    - Through mytoken
    - Through transfer code
    - Support for native application (polling codes)
- Obtain access tokens
- Tokeninfo
- Token Revocation


## mytoken 0.1.0
This is the first release of the mytoken command line client.
mytoken is still under active development and is not yet considered stable.

The first release supports the following important features:

- Obtain and store super token
- Obtain super token for usage somewhere else
- Obtain access token from super token
- Token revocation
- Super token can be created from another super token or the authorization code flow
- Super tokens can be restricted
- Content of a super token can be printed
- Super tokens are encrypted with a password or gpg key
