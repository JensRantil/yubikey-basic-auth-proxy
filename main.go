package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/GeertJohan/yubigo"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	CREDENTIALS_FILE_FLAG             = "credentials-file"
	CREDENTIALS_FILE_DEFAULT_FLAG     = "credentials.json"
	CREDENTIALS_FILE_FLAG_DESCRIPTION = "The file that stores the credentials."
)

var (
	app = kingpin.New("yubikey-basic-auth-proxy", "HTTP Proxy that adds a layer of Basic Auth that does Yubikey authentication.")

	serve                = app.Command("serve", "Run the proxy.")
	upstream             = serve.Arg("upstream", "The full URL to upstream server.").Required().URL()
	listen               = serve.Flag("listen", "What to listen on.").Default(":80").String()
	authCookieName       = serve.Flag("auth-cookie", "Name of cookie holding temporary authentication data.").Default("X-AUTHENTICATED").String()
	cookieExpiration     = serve.Flag("auth-expiration", "The duration of which a correct authentication will be persist.").Default("30m").Duration()
	authPath             = serve.Flag("auth-path", "The path on which authentication will occur. Shouldn't be an existing path upstream.").Default("/x-authenticate").String()
	cacheExpiration      = serve.Flag("cache-expiration", "The expiration duration for logins").Default("30m").Duration()
	yubicoId             = serve.Arg("yubico-api-id", "The ID used when connecting to Yubico's API.").Required().String()
	yubicoKey            = serve.Arg("yubico-api-key", "The key used when connecting to Yubico's API.").Required().String()
	serveCredentialsFile = serve.Flag(CREDENTIALS_FILE_FLAG, CREDENTIALS_FILE_FLAG_DESCRIPTION).Default(CREDENTIALS_FILE_DEFAULT_FLAG).File()

	credentials = app.Command("credentials", "Commands to modify credentials")

	add                = credentials.Command("add", "Add a credentials.")
	addCredentialsFile = add.Flag(CREDENTIALS_FILE_FLAG, CREDENTIALS_FILE_FLAG_DESCRIPTION).Default(CREDENTIALS_FILE_DEFAULT_FLAG).String()
	addUsername        = add.Arg("username", "Username to add.").Required().String()
	addYubikey         = add.Arg("yubikey", "The 12 character yubikey identifier.").Required().String()
	addPassword        = add.Arg("password", "Optional password. If not defined, it will be asked for interactively.").String()

	list                = credentials.Command("list", "List the credentials.")
	listCredentialsFile = list.Flag(CREDENTIALS_FILE_FLAG, CREDENTIALS_FILE_FLAG_DESCRIPTION).Default(CREDENTIALS_FILE_DEFAULT_FLAG).File()

	remove                = credentials.Command("delete", "Delete a credentials.")
	removeCredentialsFile = remove.Flag(CREDENTIALS_FILE_FLAG, CREDENTIALS_FILE_FLAG_DESCRIPTION).Default(CREDENTIALS_FILE_DEFAULT_FLAG).File()
	removeUsername        = remove.Arg("username", "Username to remove. Only given a single username when multiple usernames exist, will fail this command.").Required().String()
	removeYubico          = remove.Arg("yubikey", "Optional yubikey identifier if a username has multiple records.").String()

	// TODO: Support modifying a key?
)

type CookieCache interface {
	Add(cache string)
	IsStillThere(cache string) bool
}

func init() {
	app.Version("0.0.1")
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case "credentials add":
	case "credentials remove":
	case "credentials list":
	case "serve":
		var yubiAuth *yubigo.YubiAuth
		if _yubiAuth, err := yubigo.NewYubiAuth(*yubicoId, *yubicoKey); err != nil {
			log.Fatal("Could not instantiate the yubico connector:", err)
		} else {
			yubiAuth = _yubiAuth
		}

		// Instantiate the authentication proxy.

		proxy := httputil.NewSingleHostReverseProxy(*upstream)
		cache := NewCache(*cacheExpiration)

		var acl *ACLConfig
		if _acl, err := loadACLCredentials(*credentialsFile); err != nil {
			log.Fatal(err)
		} else {
			acl = _acl
		}

		authProxy := authProxyHandler{
			acl:              acl,
			authPath:         *authPath,
			authCookieName:   *authCookieName,
			yubiAuth:         yubiAuth,
			cache:            *cache,
			proxy:            proxy,
			cookieExpiration: *cacheExpiration,
		}

		// TODO: Support (and default to) TLS
		log.Fatal(http.ListenAndServe(*listen, authProxy))
	default:
		app.FatalUsage("Unrecognized command.")
	}

}
