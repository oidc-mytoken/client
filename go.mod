module github.com/oidc-mytoken/client

go 1.14

require (
	github.com/Songmu/prompter v0.5.0
	github.com/gliderlabs/ssh v0.3.3
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/oidc-mytoken/api v0.3.1-0.20220117084015-d21eb7b909ec
	github.com/oidc-mytoken/lib v0.2.2-0.20220120080933-63c77cfd245c
	github.com/oidc-mytoken/server v0.3.3-0.20220120140346-dbffc8353aad
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli/v2 v2.3.1-0.20211205195634-e8d81738896c
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985 // indirect
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914 // indirect
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/urfave/cli/v2 => github.com/zachmann/cli/v2 v2.3.1-0.20211220102037-d619fd40a704
