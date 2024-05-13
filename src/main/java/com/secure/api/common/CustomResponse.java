package com.secure.api.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * CustomResponse.
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CustomResponse {
  private String message;
  private Boolean success;
  private Object data;

  public static CustomResponse setAndGetCustomResponse(boolean success, String message, Object data) {
    return CustomResponse.builder()
            .success(success)
            .message(message)
            .data(data)
            .build();
  }
}
