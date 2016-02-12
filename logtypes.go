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
