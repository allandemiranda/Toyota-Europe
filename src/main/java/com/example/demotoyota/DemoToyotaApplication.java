package com.example.demotoyota;

import org.apache.commons.codec.binary.Base64;

import java.security.PublicKey;

public class DemoToyotaApplication {

  public static void main(String[] args) throws Exception {

    AuthenticationMechanism authenticationMechanism = new AuthenticationMechanism();

    // Some information on the Token
    AuthenticationInput userRequest = new AuthenticationInput("https://fake.url/", "NameOfUser", "OpenHomePage");

    // Id from API
    PublicKey idAPI = authenticationMechanism.getPublicKey();

    // Generate a token after authentication (Auth Controller)
    String token = authenticationMechanism.generateToken(userRequest.getAuthenticationInput(), idAPI);
    System.out.println(token);

    // Check the token stored on client to open some page (Auth Middleware)
    String payload = authenticationMechanism.validateToken(token).getPayload();
    String jsonPayload = new String(Base64.decodeBase64(payload), "UTF-8");
    System.out.println(jsonPayload);
  }

}
