package main

type CouldNotFindUsername struct {
	Username string
}

type PasswordOrOTPFailed struct {
	Username string
	Error    string
}

type CouldNotValidateAgainstYubico struct {
	Error string
}

type UnableToValidateCredentials struct {
	Username string
	Error    string
}

type UnableToLog struct {
	ErrorString string
}

type AuthenticationSuccesful struct {
	Username string
}

type Proxying struct {
	RemoteAddr string
	URL        string
}

type AskedUserToAuthenticate struct {
	RemoteAddr string
}

type UnableToGenerateRandomString struct{}
