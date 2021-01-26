package main

import (
	"github.com/oidc-mytoken/server/shared/httpClient"

	"github.com/oidc-mytoken/client/internal/commands"
	"github.com/oidc-mytoken/client/internal/utils/logger"
)

func main() {
	logger.Init()
	httpClient.Init("")
	commands.Parse()
}
