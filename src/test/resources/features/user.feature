Feature: User CRUD operations
  A client should be able to create a new User account

  Background:
    Given the caller has the given User:
      | name     | email          | password |
      | testUser | test@email.com | testPass |
    And the POST "/user" endpoint is called

  Scenario: Caller wants to get his current user
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key                | value                 |
      | header | Authorization      | Bearer {accessToken}  |
    Then the service returns HTTP 200
    And the service returns the User:
      | name     | email          |
      | testUser | test@email.com |

  Scenario: Caller wants to get his current user, but calls the endpoint that does it with the static context
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user/withStaticContext" endpoint is called:
      | type   | key                | value                 |
      | header | Authorization      | Bearer {accessToken}  |
    Then the service returns HTTP 200
    And the service returns the User:
      | name     | email          |
      | testUser | test@email.com |

  Scenario: Caller wants to get his current user, but doesn't have a valid access token
    When the GET "/user" endpoint is called:
      | type   | key                | value        |
      | header | Authorization      | Bearer test  |
    Then the service returns HTTP 401
    And the service returns a message with the error message "Invalid JWT Token"

  Scenario: Caller wants to get his current user, but uses the refresh token
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key                | value                  |
      | header | Authorization      | Bearer {refreshToken}  |
    Then the service returns HTTP 401
    And the service returns a message with the error message "Invalid access token"