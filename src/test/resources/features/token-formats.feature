Feature: Token format coverage
  The library should create and validate tokens in all three formats (JWS, JWE, nested JWE)

  @jws
  Scenario: Caller logs in and accesses a protected endpoint with JWS token format
    Given the caller has the given User:
      | name    | email         | password |
      | jwsUser | jws@email.com | jwsPass  |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email         | password | device | expires |
      | jws@email.com | jwsPass  | phone1 | false   |
    When the POST "/auth/login" endpoint is called
    Then the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the User:
      | name    | email         |
      | jwsUser | jws@email.com |

  @nested-jwe
  Scenario: Caller logs in and accesses a protected endpoint with nested JWE token format
    Given the caller has the given User:
      | name       | email            | password   |
      | nestedUser | nested@email.com | nestedPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email            | password   | device | expires |
      | nested@email.com | nestedPass | phone1 | false   |
    When the POST "/auth/login" endpoint is called
    Then the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the User:
      | name       | email            |
      | nestedUser | nested@email.com |
