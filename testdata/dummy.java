package com.whatever.something;

import org.apache.commons.lang3.StringUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;

public class SomethingHandler implements SOAPHandler<SOAPMessageContext> {
    private String someTokenPassword = "AERWEk33se";

    public SomethingHandler(ServiceProperties properties) throws FileNotFoundException {
        this.serviceProperties = properties;
        // initialize configurable properties
        populateProperties();
        // initialize crypto
        createCryptoProperties();
    }
}