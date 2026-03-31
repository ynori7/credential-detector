// This is a dummy TypeScript file for testing credential detection

const appName: string = "my-cool-app";
const password: string = "supersecure123!@#$";
let apiKey: string = "sk-1234567890abcdef1234";
var token: string = "short";

// Database connection
const dbUri = "postgres://admin:s3cr3t999@db.example.com:5432/production?sslmode=disable";

const config = {
    secret: "myappvalue12345678",
    name: "myapp",
    port: 8080,
};

// A comment with a credential: xoxb-1234567890-abcdefghij

/* A multiline comment
   with an embedded JWT: eyJhbGciOiJIUzI1NiIsInR5cCIabc.xyz.def
*/

export const accessKey: string = "AKIAIOSFODNN7EXAMPLE";

class DatabaseService {
    private dbPassword: string = "dbP@ssw0rd9876";
    protected secret: string = "cl@ssicV@lue42";
    public readonly serviceApiKey: string = "xyz789pubToken";
    private static token: string = "static-tok-abc1234";
}

interface AppConfig {
    host: string;
    port: number;
}

const dbConfig = {
    host: "localhost",
    credentials: {
        password: "nestedDbP@ss9876",
        token: "nested-tok-abc1234"
    },
    DefaultPw: "supersecret"
};
