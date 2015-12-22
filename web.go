package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/GeertJohan/yubigo"
)

type authProxyHandler struct {
	acl                   *ACLConfig
	cache                 Cache
	authPath              string
	authCookieName        string
	authNextPageQueryName string
	proxy                 *httputil.ReverseProxy
	yubiAuth              *yubigo.YubiAuth
	cookieExpiration      time.Duration
}

// Returns a boolean only (no error) to make validation of this return value easier.
func (a *authProxyHandler) validateCredentialsForEntry(entry UserEntry, username, password, yubiKey string) bool {

	// Validate username.

	if entry.Username != username {
		return false
	}

	// Validate password.

	if ok, _ := entry.PasswordHash.Test(password); !ok {
		return false
	}

	// Validate Yubikey.

	_, ok, _ := a.yubiAuth.Verify(yubiKey)
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

func (a authProxyHandler) isOnAuthenticationURL(req *http.Request) bool {
	return req.URL.Path == a.authPath
}

func (a authProxyHandler) temporaryRedirectToRealPage(resp http.ResponseWriter, req *http.Request) {
	nextPage := req.URL.Query().Get(a.authNextPageQueryName)

	if nextPage == "" {
		// Something is buggy.
		resp.WriteHeader(http.StatusBadRequest)

		// XXX: This is wrong. It not be content, but could be headers etc. Should use http.ServeContent instead.
		resp.Write([]byte(fmt.Sprintf("Expected '%s' query parameter.", a.authNextPageQueryName)))
	} else {
		temporaryRedirectTo(resp, req, nextPage)
	}
}

func temporaryRedirectTo(resp http.ResponseWriter, req *http.Request, path string) {
	http.Redirect(resp, req, path, http.StatusTemporaryRedirect)
}

func (a authProxyHandler) temporaryRedirectToAuthPath(resp http.ResponseWriter, req *http.Request) {
	temporaryRedirectTo(resp, req, a.authPath)
}

func (a authProxyHandler) authenticate(resp http.ResponseWriter, req *http.Request) {
	valid := false

	if a.isAuthenticated(req) {
		valid = true
	}

	if username, password, ok := req.BasicAuth(); ok {
		valid, _ = a.validateCredentials(username, password)
	}

	if valid {
		var randValue string
		slots := make([]byte, 32)
		if _, err := rand.Reader.Read(slots); err != nil {
			// TODO: Log
			resp.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			randValue = hex.EncodeToString(slots)
		}

		cookie := http.Cookie{
			Name:   a.authCookieName,
			Value:  randValue,
			MaxAge: int(a.cookieExpiration.Seconds()),
		}
		http.SetCookie(resp, &cookie)
		a.cache.Add(randValue)

		a.temporaryRedirectToRealPage(resp, req)
	} else {
		// Ask for authentication
		resp.Header()["WWW-Authenticate"] = []string{"Basic realm=\"Please enter your username, followed by password+yubikey\""}
		resp.WriteHeader(http.StatusUnauthorized)
	}
}

func (a authProxyHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if a.isOnAuthenticationURL(req) {
		// Authenticated
		a.authenticate(resp, req)
	} else {
		if a.isAuthenticated(req) {
			// Proxy upstream
			a.proxy.ServeHTTP(resp, req)
		} else {
			// Redirect to auth page.
			a.temporaryRedirectToAuthPath(resp, req)
		}
	}
}
