package com.example.demotoyota;

import java.util.Map;

public class AuthenticationInput {

  private final String url;
  private final String user;
  private final String permissions;

  public AuthenticationInput(String url, String user, String permissions) {
    this.url = url;
    this.user = user;
    this.permissions = permissions;
  }

  public String getUrl() {
    return url;
  }

  public String getUser() {
    return user;
  }

  public String getPermissions() {
    return permissions;
  }

  public Map<String, String> getAuthenticationInput(){
    return Map.of("url", getUrl(), "user", getUser(), "permissions", getPermissions());
  }
}
