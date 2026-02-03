package ttsig

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Skill/ttsig/signer"
)

type SignConfig struct {
	RawRequestParameters string
	RequestPayload       string
	SecDeviceID          string
	Cookie               string
	AppID                int
	LicenseID            int
	SdkVersionString     string
	SdkVersionInt        int
	Platform             int
	UnixTimestamp        float64
}

type SignedHeaders map[string]string

func SignRequest(signParams SignConfig) (SignedHeaders, error) {
	unixSeconds := int64(signParams.UnixTimestamp)
	unixMilliseconds := int64(math.Round(signParams.UnixTimestamp * 1000))
	if signParams.AppID == 0 {
		signParams.AppID = 1233
	}
	if signParams.LicenseID == 0 {
		signParams.LicenseID = 1611921764
	}
	if signParams.SdkVersionString == "" {
		signParams.SdkVersionString = "v05.00.06-ov-android"
	}
	if signParams.SdkVersionInt == 0 {
		signParams.SdkVersionInt = 167775296
	}
	if signParams.UnixTimestamp == 0 {
		signParams.UnixTimestamp = float64(time.Now().UnixNano()) / 1e9
	}

	if signParams.RawRequestParameters == "" {
		return nil, errors.New("RawParams must not be empty")
	}
	if signParams.RequestPayload == "" {
		return nil, errors.New("Payload must not be empty")
	}

	xssStub := md5Upper(signParams.RequestPayload)

	gorgonSigner := &signer.Gorgon{
		Unix:    unixSeconds,
		Params:  signParams.RawRequestParameters,
		Data:    signParams.RequestPayload,
		Cookies: signParams.Cookie,
	}

	gorgonHeader := gorgonSigner.GetValue()

	xLadon, err := (signer.Ladon{}).Encrypt(
		unixSeconds,
		int64(signParams.LicenseID),
		int64(signParams.AppID),
	)

	if err != nil {
		return nil, err
	}

	xArgus, err := signer.GetSign(
		signParams.RawRequestParameters, // IMPORTANT: raw string
		xssStub,
		unixSeconds,
		signParams.AppID,
		signParams.LicenseID,
		signParams.Platform,
		signParams.SecDeviceID,
		signParams.SdkVersionString,
		signParams.SdkVersionInt,
	)
	if err != nil {
		return nil, err
	}

	out := map[string]string{}

	for k, v := range gorgonHeader {
		out[k] = v
	}
	out["x-khronos"] = strconv.FormatInt(unixSeconds, 10)
	out["x-ss-req-ticket"] = strconv.FormatInt(unixMilliseconds, 10)
	out["content-length"] = strconv.Itoa(len(signParams.RequestPayload))
	out["x-ss-stub"] = xssStub
	out["x-ladon"] = xLadon
	out["x-argus"] = xArgus

	return out, nil
}

func md5Upper(s string) string {
	h := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
