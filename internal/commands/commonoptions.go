package commands

import (
	"encoding/json"
	"io/ioutil"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v2"
)

type commonMTOptsWrap struct {
	obtainOpts commonMTOpts
	storeOpts  commonMTOpts
}

var commonMTOptions commonMTOptsWrap

type commonMTOpts struct {
	PTOptions
	TransferCode string
	UseOIDCFlow  bool

	Capabilities         api.Capabilities
	SubtokenCapabilities api.Capabilities

	Restrictions          string
	RestrictScopes        cli.StringSlice
	RestrictAudiences     cli.StringSlice
	RestrictExp           string
	RestrictNbf           string
	RestrictIP            cli.StringSlice
	RestrictGeoIPAllow    cli.StringSlice
	RestrictGeoIPDisallow cli.StringSlice
	RestrictUsagesOther   int64
	RestrictUsagesAT      int64

	RotationStr string
	RotationObj api.Rotation
}

func (opts commonMTOptsWrap) Common(store bool) commonMTOpts {
	if !store {
		return opts.obtainOpts
	}
	sOpts := opts.storeOpts
	oOpts := opts.obtainOpts
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
	sOpts.RotationStr = getCorrectOptsStruct(sOpts.RotationStr != "", sOpts, oOpts).RotationStr
	sOpts.RotationObj.OnAT = getCorrectOptsStruct(sOpts.RotationObj.OnAT, sOpts, oOpts).RotationObj.OnAT
	sOpts.RotationObj.OnOther = getCorrectOptsStruct(sOpts.RotationObj.OnOther, sOpts, oOpts).RotationObj.OnOther
	sOpts.RotationObj.AutoRevoke = getCorrectOptsStruct(sOpts.RotationObj.AutoRevoke, sOpts, oOpts).RotationObj.AutoRevoke
	sOpts.RotationObj.Lifetime = getCorrectOptsStruct(sOpts.RotationObj.Lifetime > 0, sOpts, oOpts).RotationObj.Lifetime
	opts.storeOpts = sOpts
	return opts.storeOpts
}

func getCorrectOptsStruct(con bool, a, b commonMTOpts) commonMTOpts {
	if con {
		return a
	}
	return b
}

func (opts *commonMTOpts) parseRotationOption() error {
	rotStr := opts.RotationStr
	if rotStr == "" {
		return nil
	}
	if rotStr[0] == '{' {
		return json.Unmarshal([]byte(rotStr), &opts.RotationObj)
	}
	data, err := ioutil.ReadFile(rotStr)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &opts.RotationObj)
}

func (opts commonMTOpts) Rotation() *api.Rotation {
	rot := opts.RotationObj
	if rot.OnAT {
		return &rot
	}
	if rot.OnOther {
		return &rot
	}
	if rot.AutoRevoke {
		return &rot
	}
	if rot.Lifetime > 0 {
		return &rot
	}
	return nil
}
