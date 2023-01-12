package main

import (
	"fmt"

	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/utils/httpclient"
	"golang.org/x/net/context"

	"github.com/oidc-mytoken/client/internal/commands"
	"github.com/oidc-mytoken/client/internal/model/version"
	"github.com/oidc-mytoken/client/internal/utils/logger"
)

var ctx = context.Background()

func init() {
	ctx = context.WithValue(ctx, mytokenlib.ContextKeyUserAgent, fmt.Sprintf("mytoken client %s", version.VERSION))
}

func main() {
	logger.Init()
	httpclient.Init("", "") // This useragent is not used by lib, so not needed
	mytokenlib.SetClient(httpclient.Do().GetClient())
	mytokenlib.SetContext(ctx)
	commands.Parse()
}
