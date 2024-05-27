Feature: Auth operations
  The Authorizer, Validators, and TokenFactory should work and streamline the auth operations

  Background:
    Given the caller has the given User:
      | name     | email         | password |
      | testUser | test@email.com| testPass |
    And the POST "/user" endpoint is called

  Scenario: Caller logs in
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    When the POST "/auth/login" endpoint is called
    Then the service returns HTTP 200
    And the service returns the AuthResponse

  Scenario: Caller refreshes access token
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/auth/token" endpoint is called:
      | type   | key                | value                  |
      | header | Authorization      | Bearer {refreshToken}  |
    Then the service returns HTTP 200
    And the service returns the AccessToken
