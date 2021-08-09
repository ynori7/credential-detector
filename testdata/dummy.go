package testdata

var okayVar = "some stuff"

var internalSecret string = "asdfasdfasdf"

var (
	anotherOkayOne = "blah"
	authToken      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

const (
	AccessCode     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	API_KEY_HEADER = "X-Api-Key"
)

var RealPostgresUri = "postgres://myuser:password123@blah.com:5432/mydb?sslmode=disable"
var TestPostgresUri = "postgres://myuser:password123@localhost:5432/mydb?sslmode=disable"

/*
Multiline comment
postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable
*/

func blah() {
	badPassword := "stupid"

	emptyPassword := ""

	if badPassword == emptyPassword {
		//do nothing
	}
}

type Config struct {
	Secret string
}

var conf = Config{
	Secret: "blah",
}

var PasswordFormat = "([0-9]+):(.+)"

var StatusAlternatives = "Alternatives" //variable name contains sAlt. Should not match the "salt" pattern

var blahToken = "password"

// blop is a function that does nothing
func blop() {
	// this is a local comment
	// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}