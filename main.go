package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"log"
	"os"
	"strings"
)

var sanitizedHeaders = map[string]string{"org": "org", "user_uuid": "user_uuid", "principal_type": "principal_type"}

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
			log.Println(err)
			return types.ActionPause
		}
	}

	headers, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		log.Println(err)
		return types.ActionContinue
	}
	if numHeaders > 0 {
		headerMap := map[string]string{}
		for i := range headers {
			headerMap[headers[i][0]] = headers[i][1]
		}
		tokenString, err := extractToken(headerMap["Authorization"])
		if err != nil {
			log.Println(err)
			return types.ActionContinue
		}
		claims, err := decodeToken(tokenString)
		if err != nil {
			log.Println(err)
			return types.ActionContinue
		}
		claimMap := claims.(map[string]interface{})
		for k, v := range sanitizedHeaders {
			err = proxywasm.AddHttpRequestHeader(k, fmt.Sprint(claimMap[v]))
			if err != nil {
				log.Println(err)
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

func decodeToken(tokenString string) (interface{}, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return os.Getenv("TOKEN_SECRET"), nil
	})
}
