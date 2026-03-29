// This is a dummy JavaScript file for testing credential detection

const appName = "my-cool-app";
const password = "supersecure123!@#$";
let apiKey = "sk-1234567890abcdef1234";
var token = "short";

// Database connection
const dbUri = "postgres://admin:s3cr3t999@db.example.com:5432/production?sslmode=disable";

const config = {
    secret: "myappvalue12345678",
    name: "myapp",
    port: 8080,
};

module.exports.API_KEY = "abcdef1234567890xyzzy";

// A comment with a credential: xoxb-1234567890-abcdefghij

/* A multiline comment
   with an embedded JWT: eyJhbGciOiJIUzI1NiIsInR5cCIabc.xyz.def
*/

exports.salt = "a1b2c3d4e5f6g7h8";

function doSomething() {
    console.log("nothing to see here");
    return true;
}

export const accessKey = "AKIAIOSFODNN7EXAMPLE";

const dbConfig = {
    host: "localhost",
    credentials: {
        password: "nestedDbP@ss9876",
        token: "nested-tok-abc1234"
    },
    PreferredBackupWindow: "01:00-02:00",
    DefaultPw: "supersecret"
};
