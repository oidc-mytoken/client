module github.com/oidc-mytoken/client

go 1.16

require (
	github.com/Songmu/prompter v0.5.0
	github.com/gliderlabs/ssh v0.3.3
	github.com/oidc-mytoken/api v0.5.1
	github.com/oidc-mytoken/lib v0.3.3
	github.com/oidc-mytoken/server v0.4.1
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/urfave/cli/v2 v2.3.1-0.20211205195634-e8d81738896c
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/urfave/cli/v2 => github.com/zachmann/cli/v2 v2.3.1-0.20211220102037-d619fd40a704
