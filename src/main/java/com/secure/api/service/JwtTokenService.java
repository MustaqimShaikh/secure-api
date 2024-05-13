package com.secure.api.service;

import com.secure.api.common.CustomResponse;
import com.secure.api.common.MessageEnum;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtTokenService {

  @Value("${encryption.secret.key}")
  private String secretKey;

  @Value("${encryption.secret.salt}")
  private String secretSalt;

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenService.class);

  public CustomResponse createCustomToken() {
    LOGGER.info("Creating JwtToken and Secret");
    return createJwtTokenAndSecret("1", "Secure API Communication");
  }
  public CustomResponse createJwtTokenAndSecret(String id, String subject) {
    LOGGER.info("Creating JwtToken and Secret from Id: {} and Subject: {}", id, subject);
    // Creating random string
    String encryptor = UUID.randomUUID().toString();
    // Convert string to byte array
    byte[] bytes = encryptor.getBytes(StandardCharsets.UTF_8);
    // Encode byte array to Base64
    byte[] base64Bytes = Base64.getEncoder().encode(bytes);
    //The JWT signature algorithm we will be using to sign the token
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    //We will sign our JWT with our ApiKey secret
    Key signingKey = new SecretKeySpec(base64Bytes, signatureAlgorithm.getJcaName());
    //Let's set the JWT Claims
    JwtBuilder builder = Jwts.builder().setId(id)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setSubject(subject)
            .setIssuer("LITTLE_PINGER")
            .signWith(signingKey, signatureAlgorithm);
    Map<String, String> jwtTokenSecretPair = new HashMap<>();
    jwtTokenSecretPair.put("jwtToken", builder.compact());
    jwtTokenSecretPair.put("secret", Encryptors.text(secretKey, secretSalt).encrypt(encryptor));
    return CustomResponse.setAndGetCustomResponse(true, MessageEnum.JWT_TOKEN_AND_SECRET.name(), jwtTokenSecretPair);
  }

  public Claims decodeJWT(String jwtToken, String secret) {
    try {
      LOGGER.info("Decoding JwtToken: {} and Secret: {}", jwtToken, secret);
      // Decode the secret first
      String decrypt = Encryptors.text(secretKey, secretSalt).decrypt(secret);
      // Convert the decrypted secret back to byte array
      byte[] bytes = decrypt.getBytes(StandardCharsets.UTF_8);
      // Decode the byte array from Base64
      byte[] base64Bytes = Base64.getEncoder().encode(bytes);
      SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
      // Parse the JWT jwtToken using the decoded secret
      return Jwts.parserBuilder()
              .setSigningKey(new SecretKeySpec(base64Bytes, signatureAlgorithm.getJcaName()))
              .build()
              .parseClaimsJws(jwtToken)
              .getBody();
    } catch (Exception e) {
      LOGGER.error("Error while decoding jwtToken: {} and secret: {}, Error: {}",
              jwtToken, secret, e.getMessage());
      e.printStackTrace();
      return null;
    }
  }

}
