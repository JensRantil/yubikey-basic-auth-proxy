package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/GeertJohan/yubigo"
)

type authProxyHandler struct {
	acl              *ACLConfig
	cache            Cache
	authCookieName   string
	proxy            *httputil.ReverseProxy
	yubiAuth         *yubigo.YubiAuth
	cookieExpiration time.Duration
}

// Returns a boolean only (no error) to make validation of this return value easier.
func (a *authProxyHandler) validateCredentialsForEntry(entry UserEntry, username, password, yubiKey string) bool {

	// Validate username.

	if entry.Username != username {
		return false
	}

	// Validate password.

	if ok, err := entry.PasswordHash.Test(password); !ok {
		log.Println("Could not validate password:", err)
		return false
	}

	// Validate Yubikey.

	_, ok, err := a.yubiAuth.Verify(yubiKey)
	if err != nil {
		log.Println("Could not validate against Yubico:", err)
	}
	return ok
}

func (a *authProxyHandler) validateCredentials(username string, basicAuthPassword string) (bool, error) {
	if len(username) == 0 {
		return false, errors.New("Username must not be empty.")
	}

	if len(basicAuthPassword) < 44 {
		return false, errors.New("Yubikey missing.")
	}
	passwordString := basicAuthPassword[0 : len(basicAuthPassword)-44]
	yubikeyString := basicAuthPassword[len(basicAuthPassword)-44 : len(basicAuthPassword)]

	for _, entry := range a.acl.Entries {
		if a.validateCredentialsForEntry(entry, username, passwordString, yubikeyString) {
			return true, nil
		}
	}

	return false, nil
}

func (a authProxyHandler) isAuthenticated(req *http.Request) bool {
	if cookie, err := req.Cookie(a.authCookieName); err != nil {
		return false
	} else {
		return a.cache.IsStillThere(cookie.Value)
	}
}

func generateRandomString(bytesSource int) (string, error) {
	slots := make([]byte, 32)
	if _, err := rand.Reader.Read(slots); err != nil {
		return "", err
	} else {
		return hex.EncodeToString(slots), nil
	}

}

func (a authProxyHandler) stripAuthCookie(req *http.Request) {
	if cookieHeaders, ok := req.Header["Cookie"]; ok {
		for i, cookieHeader := range cookieHeaders {
			cookies := strings.Split(cookieHeader, "; ")
			newCookies := make([]string, 0)
			for _, cookie := range cookies {
				if !strings.HasPrefix(cookie, a.authCookieName+"=") {
					newCookies = append(newCookies, cookie)
				}
			}
			cookieHeaders[i] = strings.Join(newCookies, "; ")
		}
	}
}

func (a authProxyHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	valid := false

	if a.isAuthenticated(req) {
		valid = true
	}

	if !valid {
		if username, password, ok := req.BasicAuth(); ok {
			valid, _ = a.validateCredentials(username, password)
		}
	}

	if valid {
		var randValue string
		if _randValue, err := generateRandomString(32); err != nil {
			// TODO: Log
			resp.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			randValue = _randValue
		}

		cookie := http.Cookie{
			Name:   a.authCookieName,
			Value:  randValue,
			MaxAge: int(a.cookieExpiration.Seconds()),
		}
		http.SetCookie(resp, &cookie)
		a.cache.Add(randValue)

		// Important we don't proxy our username and password upstream!
		delete(req.Header, "Authorization")

		// Don't proxy the auth cookie.
		a.stripAuthCookie(req)

		a.proxy.ServeHTTP(resp, req)
	} else {
		// Ask for authentication
		resp.Header()["WWW-Authenticate"] = []string{"Basic realm=\"Please enter your username, followed by password+yubikey\""}
		resp.WriteHeader(http.StatusUnauthorized)
	}
}
