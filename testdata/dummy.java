package com.whatever.something;

import org.apache.commons.lang3.StringUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;

public class SomethingHandler implements SOAPHandler<SOAPMessageContext> {
    private String someTokenPassword = "AERWEk33se"; // default value

    public SomethingHandler(ServiceProperties properties) throws FileNotFoundException {
        this.serviceProperties = properties;
        // initialize configurable properties
        populateProperties();
        // initialize crypto
        createCryptoProperties();
    }

    const String INTERNAL_API_KEY = 'kiu#pKJSDK;LE';
    // this is a local comment
    // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    public blah() {
        NewStaticCredentials("AKIAYTHMXXXGSVYYYWE6", "rP22kgSajDwOyWVU/iiii1UEdJk333QUbxwtiVCe");
    }
}

/*
 * This is a multiline comment
 * it contains postgres://myuser:password123@somepostgresdb:5432/mydb?sslmode=disable
 */
