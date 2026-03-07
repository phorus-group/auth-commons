Feature: Authentication performance metrics
  When metrics are enabled and a MeterRegistry is on the classpath,
  authentication duration and failure patterns are recorded as timers.

  Background:
    Given the caller has the given User:
      | name     | email          | password |
      | testUser | test@email.com | testPass |
    And the POST "/user" endpoint is called

  Scenario: Successful authentication is timed
    Given the caller has the given login information:
      | email          | password | device | expires |
      | test@email.com | testPass | phone1 | false   |
    When the POST "/auth/login" endpoint is called
    Then the service returns HTTP 200
    And the timer "auth.authentication" is recorded with mode "standalone" and exception "None"

  Scenario: Failed authentication is timed with exception type
    When the GET "/user" endpoint is called
    Then the service returns HTTP 401
    And the timer "auth.authentication" is recorded with mode "standalone" and exception "Unauthorized"
