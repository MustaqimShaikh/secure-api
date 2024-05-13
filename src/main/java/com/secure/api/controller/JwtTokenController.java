package com.secure.api.controller;

import com.secure.api.common.CustomResponse;
import com.secure.api.service.JwtTokenService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Validated
@CrossOrigin
@RestController
@RequestMapping("/api/jwt")
public class JwtTokenController {

  @Autowired
  private JwtTokenService jwtTokenService;

  @PostMapping("/token")
  public ResponseEntity<CustomResponse> createCustomToken() {
    CustomResponse response = jwtTokenService.createCustomToken();
    return new ResponseEntity<>(response, HttpStatus.OK);
  }

  @PostMapping("/decode")
  public ResponseEntity<Claims> decodeToken(@RequestHeader("JwtAuthorization") String authToken,
                                            @RequestHeader("Secret") String authSecret) {
    Claims claims = jwtTokenService.decodeJWT(authToken.split(" ")[1], authSecret);
    return new ResponseEntity<>(claims, HttpStatus.OK);
  }
}
