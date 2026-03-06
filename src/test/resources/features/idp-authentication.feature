@idp
Feature: IdP token authentication
  The library should validate IdP-issued tokens via JWKS in IDP_DELEGATED mode

  Scenario: Service accepts a valid JWS token from an IdP
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has a valid IdP JWS token with subject "550e8400-e29b-41d4-a716-446655440000" and privileges "read write"
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 200
    And the response contains userId "550e8400-e29b-41d4-a716-446655440000"
    And the response contains privilege "read"
    And the response contains privilege "write"

  Scenario: Service accepts a nested JWE token from an IdP
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has a valid IdP nested JWE token with subject "660e8400-e29b-41d4-a716-446655440000" and privileges "admin"
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 200
    And the response contains userId "660e8400-e29b-41d4-a716-446655440000"
    And the response contains privilege "admin"

  Scenario: Validators accept a valid IdP token with custom claim
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has a valid IdP JWS token with subject "880e8400-e29b-41d4-a716-446655440000" and privileges "read" and claim "tokenThingy" = "true"
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 200
    And the response contains privilege "read"

  Scenario: Validators reject an IdP token with invalid custom claim
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has a valid IdP JWS token with subject "990e8400-e29b-41d4-a716-446655440000" and privileges "read" and claim "tokenThingy" = "false"
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 401

  Scenario: Service rejects a token signed with an unknown key
    Given the IdP JWKS endpoint serves the signing public key
    And the caller has an IdP token signed with an unknown key
    When the GET "/protected/me" endpoint is called:
      | type   | key           | value             |
      | header | Authorization | Bearer {idpToken} |
    Then the service returns HTTP 401
