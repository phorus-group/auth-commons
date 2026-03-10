@apikey
Feature: Dual authentication (API key + JWT token)
  When both filters are enabled, endpoints require both API key and JWT token
  unless the path is in one filter's ignore list

  Background:
    Given the caller has the given User:
      | name     | email          | password |
      | testUser | test@email.com | testPass |
    And the POST "/user" endpoint is called

  Scenario: Dual auth endpoint requires both API key and token
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/api-key-protected/dual" endpoint is called:
      | type   | key           | value                  |
      | header | X-API-KEY     | test-default-key       |
      | header | Authorization | Bearer {accessToken}   |
    Then the service returns HTTP 200
    And the response contains keyId "default"

  Scenario: Dual auth endpoint fails with API key but no token
    When the GET "/api-key-protected/dual" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | test-default-key   |
    Then the service returns HTTP 401

  Scenario: Dual auth endpoint fails with token but no API key
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/api-key-protected/dual" endpoint is called:
      | type   | key           | value                  |
      | header | Authorization | Bearer {accessToken}   |
    Then the service returns HTTP 401

  Scenario: Token-ignored path only requires API key
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | test-default-key   |
    Then the service returns HTTP 200
    And the response contains keyId "default"
