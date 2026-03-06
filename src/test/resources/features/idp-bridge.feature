@idp-bridge
Feature: IdP bridge authentication
  The library should support IDP_BRIDGE mode where an IdP token is validated and exchanged
  for a self-issued token that is then used on protected endpoints

  Scenario: Bridge login with IdP JWS token and access protected endpoint with self-issued token
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has a valid IdP JWS token with subject "770e8400-e29b-41d4-a716-446655440000" and privileges "read write"
    When the POST "/bridge/login" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 200
    And the response contains a self-issued access token
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the response contains privilege "read"
    And the response contains privilege "write"
