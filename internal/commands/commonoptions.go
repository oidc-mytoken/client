package commands

import (
	"github.com/oidc-mytoken/api/v0"
	"github.com/zachmann/cli/v2"
)

type commonMTOptsWrap struct {
	obtainOpts commonMTOpts
	storeOpts  commonMTOpts
}

var commonMTOptions commonMTOptsWrap

type commonMTOpts struct {
	*PTOptions
	TransferCode string
	UseOIDCFlow  bool

	Capabilities         api.Capabilities
	SubtokenCapabilities api.Capabilities
	Restrictions         string

	RestrictScopes        cli.StringSlice
	RestrictAudiences     cli.StringSlice
	RestrictExp           string
	RestrictNbf           string
	RestrictIP            cli.StringSlice
	RestrictGeoIPAllow    cli.StringSlice
	RestrictGeoIPDisallow cli.StringSlice
	RestrictUsagesOther   int64
	RestrictUsagesAT      int64
}

func (opts commonMTOptsWrap) Common(store bool) commonMTOpts {
	if !store {
		return opts.obtainOpts
	}
	sOpts := opts.storeOpts
	oOpts := opts.obtainOpts
	sOpts.PTOptions = getCorrectOptsStruct(sOpts.PTOptions != nil, sOpts, oOpts).PTOptions
	sOpts.PTOptions.Provider = getCorrectOptsStruct(sOpts.PTOptions.Provider != "", sOpts, oOpts).PTOptions.Provider
	sOpts.PTOptions.Name = getCorrectOptsStruct(sOpts.PTOptions.Name != "", sOpts, oOpts).PTOptions.Name
	sOpts.PTOptions.Mytoken = getCorrectOptsStruct(sOpts.PTOptions.Mytoken != "", sOpts, oOpts).PTOptions.Mytoken
	sOpts.PTOptions.MytokenPrompt = getCorrectOptsStruct(sOpts.PTOptions.MytokenPrompt, sOpts, oOpts).PTOptions.MytokenPrompt
	sOpts.PTOptions.MytokenFile = getCorrectOptsStruct(sOpts.PTOptions.MytokenFile != "", sOpts, oOpts).PTOptions.MytokenFile
	sOpts.PTOptions.MytokenEnv = getCorrectOptsStruct(sOpts.PTOptions.MytokenEnv != "", sOpts, oOpts).PTOptions.MytokenEnv
	sOpts.TransferCode = getCorrectOptsStruct(sOpts.TransferCode != "", sOpts, oOpts).TransferCode
	sOpts.UseOIDCFlow = getCorrectOptsStruct(sOpts.UseOIDCFlow, sOpts, oOpts).UseOIDCFlow
	sOpts.Capabilities = getCorrectOptsStruct(len(sOpts.Capabilities) > 0, sOpts, oOpts).Capabilities
	sOpts.SubtokenCapabilities = getCorrectOptsStruct(len(sOpts.SubtokenCapabilities) > 0, sOpts, oOpts).SubtokenCapabilities
	sOpts.Restrictions = getCorrectOptsStruct(sOpts.Restrictions != "", sOpts, oOpts).Restrictions
	sOpts.RestrictScopes = getCorrectOptsStruct(len(sOpts.RestrictScopes.Value()) > 0, sOpts, oOpts).RestrictScopes
	sOpts.RestrictAudiences = getCorrectOptsStruct(len(sOpts.RestrictAudiences.Value()) > 0, sOpts, oOpts).RestrictAudiences
	sOpts.RestrictExp = getCorrectOptsStruct(sOpts.RestrictExp != "", sOpts, oOpts).RestrictExp
	sOpts.RestrictNbf = getCorrectOptsStruct(sOpts.RestrictNbf != "", sOpts, oOpts).RestrictNbf
	sOpts.RestrictIP = getCorrectOptsStruct(len(sOpts.RestrictIP.Value()) > 0, sOpts, oOpts).RestrictIP
	sOpts.RestrictGeoIPAllow = getCorrectOptsStruct(len(sOpts.RestrictGeoIPAllow.Value()) > 0, sOpts, oOpts).RestrictGeoIPAllow
	sOpts.RestrictGeoIPDisallow = getCorrectOptsStruct(len(sOpts.RestrictGeoIPDisallow.Value()) > 0, sOpts, oOpts).RestrictGeoIPDisallow
	sOpts.RestrictUsagesOther = getCorrectOptsStruct(sOpts.RestrictUsagesOther > 0, sOpts, oOpts).RestrictUsagesOther
	sOpts.RestrictUsagesAT = getCorrectOptsStruct(sOpts.RestrictUsagesAT > 0, sOpts, oOpts).RestrictUsagesAT
	opts.storeOpts = sOpts
	return opts.storeOpts
}

func getCorrectOptsStruct(con bool, a, b commonMTOpts) commonMTOpts {
	if con {
		return a
	}
	return b
}
