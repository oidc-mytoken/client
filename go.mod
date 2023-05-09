module github.com/oidc-mytoken/client

go 1.16

require (
	github.com/Songmu/prompter v0.5.1
	github.com/gliderlabs/ssh v0.3.5
	github.com/mdp/qrterminal/v3 v3.0.0
	github.com/oidc-mytoken/api v0.10.0
	github.com/oidc-mytoken/lib v0.7.0
	github.com/oidc-mytoken/utils v0.1.2
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/urfave/cli/v2 v2.3.1-0.20211205195634-e8d81738896c
	golang.org/x/net v0.10.0
	golang.org/x/term v0.8.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/urfave/cli/v2 => github.com/zachmann/cli/v2 v2.3.1-0.20211220102037-d619fd40a704
