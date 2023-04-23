package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"strings"
	"time"
)

var sanitizedHeaders = map[string]string{"org": "org", "user_uuid": "user_uuid", "principal_type": "principal_type"}
var keySetCache map[string]jwk

const tick = 15 * time.Second

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{contextID: contextID}
}

type pluginContext struct {
	types.DefaultPluginContext
	contextID uint32
	callBack  func(numHeaders, bodySize, numTrailers int)
}

func (*pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpAuthRandom{contextID: contextID}
}

type httpAuthRandom struct {
	types.DefaultHttpContext
	contextID uint32
}

func (ctx *httpAuthRandom) OnHttpRequestHeaders(numHeaders int, _ bool) types.Action {
	for k, _ := range sanitizedHeaders {
		err := proxywasm.RemoveHttpRequestHeader(k)
		if err != nil {
			proxywasm.LogErrorf("error sanitizing headers %v", err)
			err = proxywasm.SendHttpResponse(500, nil, []byte("error sanitizing headers"), -1)
			if err != nil {
				panic(err)
			}
			return types.ActionPause
		}
	}

	if numHeaders > 0 {
		headers, err := proxywasm.GetHttpRequestHeaders()
		if err != nil {
			proxywasm.LogErrorf("error reading headers %v", err)
			return types.ActionContinue
		}
		var authHeader string
		for i := range headers {
			if headers[i][0] == "Authorization" {
				authHeader = headers[i][1]
				break
			}
		}
		if authHeader != "" {
			tokenString, err := extractToken(authHeader)
			if err != nil {
				proxywasm.LogErrorf("error extracting token %v", err)
				return types.ActionContinue
			}
			claims, err := decodeToken(tokenString, keySetCache)
			if err != nil {
				proxywasm.LogErrorf("error decoding token %v", err)
				return types.ActionContinue
			}
			for k, v := range sanitizedHeaders {
				err = proxywasm.AddHttpRequestHeader(k, fmt.Sprint(claims.Header[v]))
				if err != nil {
					proxywasm.LogErrorf("error adding header [%s:%s] %v", k, claims.Header[v], err)
				}
			}
		}
	}
	return types.ActionContinue
}

func extractToken(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header")
	}
	return parts[1], nil
}

func decodeToken(tokenString string, keySet map[string]jwk) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid header not found")
		}
		if _, ok := keySet[kid]; !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		return token, nil
	})
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	if err := proxywasm.SetTickPeriodMilliSeconds(uint32(tick.Milliseconds())); err != nil {
		proxywasm.LogCriticalf("failed to set tick period: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) OnTick() {
	//TODO cache jwks
}

type jwk struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5C []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	X5T string   `json:"x5t"`
}
