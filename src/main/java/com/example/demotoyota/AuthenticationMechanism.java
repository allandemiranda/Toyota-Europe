package com.example.demotoyota;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class AuthenticationMechanism {

  private final PublicKey rsaPublicKey;
  private final Algorithm algorithm;

  public AuthenticationMechanism() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keypair = keyPairGenerator.generateKeyPair();
    rsaPublicKey = keypair.getPublic();
    algorithm = Algorithm.RSA256((RSAPublicKey) rsaPublicKey, (RSAPrivateKey) keypair.getPrivate());
  }

  public PublicKey getPublicKey() {
    return rsaPublicKey;
  }

  public String generateToken(Map<String, String> data, PublicKey publicKey) {
    if (rsaPublicKey.equals(publicKey)) {
      try {
        Builder builder = JWT.create().withIssuer("auth0").withExpiresAt(Date.from(Instant.now().plusSeconds(300)));
        builder.withPayload(data);
        return builder.sign(algorithm);
      } catch (JWTCreationException exception) {
        throw new RuntimeException("Invalid Signing configuration / Couldn't convert Claims.");
      }
    } else {
      return "Wrong API";
    }
  }

  public DecodedJWT validateToken(String token) {
    try {
      JWTVerifier jwtVerifier = JWT.require(algorithm).withIssuer("auth0").build();
      return jwtVerifier.verify(token);
    } catch (JWTVerificationException exception) {
      throw new RuntimeException("Invalid signature/claims");
    }
  }

}
