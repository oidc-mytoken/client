package utils

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/server/shared/utils/unixtime"

	"github.com/oidc-mytoken/client/internal/utils/duration"
)

func ParseTime(t string) (int64, error) {
	if t == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(t, 10, 64)
	if err == nil {
		if t[0] == '+' {
			return int64(unixtime.InSeconds(i)), nil
		}
		return i, nil
	}
	if t[0] == '+' {
		d, err := duration.ParseDuration(t[1:])
		return int64(unixtime.New(time.Now().Add(d))), err
	}
	tt, err := time.ParseInLocation("2006-01-02 15:04", t, time.Local)
	return int64(unixtime.New(tt)), err
}

type restrictionWT struct {
	api.Restriction
	ExpiresAt string `json:"exp"`
	NotBefore string `json:"nbf"`
}

type APIRestriction api.Restriction

func (r *APIRestriction) UnmarshalJSON(data []byte) error {
	rr := restrictionWT{}
	if err := json.Unmarshal(data, &rr); err != nil {
		return err
	}
	t, err := ParseTime(rr.ExpiresAt)
	if err != nil {
		return err
	}
	rr.Restriction.ExpiresAt = t
	t, err = ParseTime(rr.NotBefore)
	if err != nil {
		return err
	}
	rr.Restriction.NotBefore = t
	*r = APIRestriction(rr.Restriction)
	return nil
}
