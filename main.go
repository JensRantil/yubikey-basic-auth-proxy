package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"syscall"

	"github.com/GeertJohan/yubigo"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	STDIN_PASSWORD_ARG = "-"
)

var (
	app             = kingpin.New("yubikey-basic-auth-proxy", "HTTP Proxy that adds a layer of Basic Auth that does Yubikey authentication.").Version("0.0.1")
	credentialsFile = app.Flag("credentials-file", "The file that stores the credentials.").Default("credentials.json").String()
	logLevelFlag    = app.Flag("log-level", "Set log level.").Default("INFO").Enum("DEBUG", "INFO", "WARN", "ERROR")

	serve            = app.Command("serve", "Run the proxy.")
	upstream         = serve.Arg("upstream", "The full URL to upstream server.").Required().URL()
	listen           = serve.Flag("listen", "What to listen on.").Default(":80").String()
	authCookieName   = serve.Flag("auth-cookie", "Name of cookie holding temporary authentication data.").Default("X-AUTHENTICATED").String()
	cookieExpiration = serve.Flag("auth-expiration", "The duration of which a correct authentication will be persist.").Default("30m").Duration()
	cacheExpiration  = serve.Flag("cache-expiration", "The expiration duration for logins").Default("30m").Duration()
	yubicoId         = serve.Arg("yubico-api-id", "The ID used when connecting to Yubico's API.").Required().String()
	yubicoKey        = serve.Arg("yubico-api-key", "The key used when connecting to Yubico's API.").Required().String()
	insecure         = serve.Flag("insecure", "Whether").Default("false").Bool()
	certificateFile  = serve.Flag("certificate-file", "Public key file for TLS.").ExistingFile()
	privateKeyFile   = serve.Flag("private-key-file", "Private key file for TLS.").ExistingFile()

	credentials = app.Command("credentials", "Commands to modify credentials.")

	initialize = credentials.Command("init", "Initialize ACL config.")

	add         = credentials.Command("add", "Add a credentials.")
	addUsername = add.Arg("username", "Username to add.").Required().String()
	addYubikey  = add.Arg("yubikey", "The 12 character yubikey identifier. Can also be a Yubikey OTP, which automatically will be truncated.").Required().String()
	addPassword = add.Arg("password", "Optional password. If not defined, it will be asked for interactively.").Default(STDIN_PASSWORD_ARG).String()

	list = credentials.Command("list", "List the credentials.")

	remove         = credentials.Command("remove", "Delete a credentials.")
	removeUsername = remove.Arg("username", "Username to remove. Only given a single username when multiple usernames exist, will fail this command.").Required().String()
	removeYubico   = remove.Arg("yubikey", "Optional yubikey identifier if a username has multiple records.").String()
)

type CookieCache interface {
	Add(cache string)
	IsStillThere(cache string) bool
}

func loadACLCredentials(filename string) (*ACLConfig, error) {
	var file *os.File
	if _file, err := os.Open(filename); err != nil {
		return nil, err
	} else {
		file = _file
	}
	defer file.Close()

	if result, err := NewACLConfigFromReader(file); err == nil && result.Version != 1 {
		return result, errors.New("Unsupported version of ACL configuration.")
	} else {
		return result, err
	}
}

func saveACLCredentials(filename string, aclConfig *ACLConfig) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return aclConfig.WriteTo(file)
}

var (
	logger MethodLogger
)

func initLogging() {
	// Not entirely pretty. Is there a better solution?
	logLevel, existed := logLevelByName[*logLevelFlag]
	if !existed {
		log.Fatalln("Could not find log level:", *logLevelFlag)
	}

	json := &JSONOutputter{
		os.Stderr,
	}
	recordLogger := &LogRecordLogger{
		json,
	}
	filteredLogger := &LogLevelFilter{
		logLevel,
		recordLogger,
	}
	logger = MethodLogger{
		filteredLogger,
	}
}

func readPasswordFromStdin() string {
	oldState, err := terminal.MakeRaw(syscall.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(syscall.Stdin, oldState)

	var password []byte
	password, err = terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	return string(password)
}

func main() {
	flagCommand := kingpin.MustParse(app.Parse(os.Args[1:]))

	initLogging()

	switch flagCommand {
	case "credentials init":
		aclConfig := NewACLConfig()
		// TODO: Fail if file already exists. Possibly support forcing recreation of it.
		if err := saveACLCredentials(*credentialsFile, aclConfig); err != nil {
			log.Fatal(err)
		}
	case "credentials add":
		// TODO: Support interactive input of password so that it doesn't end up in shell history.

		var aclConfig *ACLConfig
		if _aclConfig, err := loadACLCredentials(*credentialsFile); err != nil {
			if err != os.ErrNotExist {
				log.Fatal("Could not load credentials:", err)
			} else {
				aclConfig = NewACLConfig()
			}
		} else {
			aclConfig = _aclConfig
		}

		truncatedYubikey := *addYubikey
		if len(truncatedYubikey) < 12 {
			log.Fatal("Yubikey must be at least 12 characters.")
		}
		truncatedYubikey = truncatedYubikey[0:12]

		for _, entry := range aclConfig.Entries {
			if entry.Username == *addUsername && entry.Yubikey == truncatedYubikey {
				log.Fatal("The (username, yubikey) is already added. Please execute 'yubikey-basic-auth-proxy credentials remove ", entry.Username, " ", entry.Yubikey, "' before adding a new one.")
			}
		}

		if *addPassword == STDIN_PASSWORD_ARG {
			fmt.Print("Password: ")
			*addPassword = readPasswordFromStdin()
		}

		var newEntry *UserEntry
		if e, err := NewUserEntry(*addUsername, *addPassword, truncatedYubikey, DefaultScryptData); err != nil {
			log.Fatal(err)
		} else {
			newEntry = e
		}

		aclConfig.Entries = append(aclConfig.Entries, *newEntry)

		if err := saveACLCredentials(*credentialsFile, aclConfig); err != nil {
			log.Fatal(err)
		}

	case "credentials remove":
		var aclConfig *ACLConfig
		if _aclConfig, err := loadACLCredentials(*credentialsFile); err != nil {
			if err != os.ErrNotExist {
				log.Fatal("Could not load credentials:", err)
			} else {
				aclConfig = NewACLConfig()
			}
		} else {
			aclConfig = _aclConfig
		}

		filteredEntries := make([]UserEntry, 0)
		for _, entry := range aclConfig.Entries {
			if entry.Username != *removeUsername && (removeYubico == nil || entry.Yubikey != *removeYubico) {
				filteredEntries = append(filteredEntries, entry)
			}
		}
		aclConfig.Entries = filteredEntries

		if err := saveACLCredentials(*credentialsFile, aclConfig); err != nil {
			log.Fatal(err)
		}

	case "credentials list":
		aclConfig, err := loadACLCredentials(*credentialsFile)
		if err != nil {
			log.Fatal("Could not load credentials:", err)
		}

		for _, entry := range aclConfig.Entries {
			fmt.Printf("username: %s                 yubikey: %s\n", entry.Username, entry.Yubikey)
		}

	case "serve":

		if !xor(*insecure, *certificateFile != "" && *privateKeyFile != "") {
			app.FatalUsage("Either set certificate and private key for TLS (recommended), or set --insecure flag.")
		}

		var yubiAuth *yubigo.YubiAuth
		if _yubiAuth, err := yubigo.NewYubiAuth(*yubicoId, *yubicoKey); err != nil {
			log.Fatal("Could not instantiate the yubico connector:", err)
		} else {
			yubiAuth = _yubiAuth
		}

		// Instantiate the authentication proxy.

		proxy := httputil.NewSingleHostReverseProxy(*upstream)
		cache := NewCache(*cacheExpiration)
		go cache.Start()
		defer cache.Stop() // Here for clarity.

		var acl *ACLConfig
		if _acl, err := loadACLCredentials(*credentialsFile); err != nil {
			log.Fatal("Could not load credentials:", err)
		} else {
			acl = _acl
		}

		authProxy := authProxyHandler{
			acl:              acl,
			authCookieName:   *authCookieName,
			yubiAuth:         yubiAuth,
			cache:            *cache,
			proxy:            proxy,
			cookieExpiration: *cacheExpiration,
		}

		if *insecure {
			log.Fatal(http.ListenAndServe(*listen, authProxy))
		} else {
			log.Fatal(http.ListenAndServeTLS(*listen, *certificateFile, *privateKeyFile, authProxy))
		}
	default:
		app.FatalUsage("Unrecognized command.")
	}

}
