@privilege-gates
Feature: Privilege gates
  The token filter enforces privilege-level access control on configured paths after
  successful authentication. Requests missing a required privilege receive 403 Forbidden.

  Scenario: Allowed when user holds the required privilege
    Given the given User exists:
      | name      | email           | passwordHash |
      | gateUser  | gate@test.com   | hash123      |
    And the caller has a token for that user with privileges "admin" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/admin" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200

  Scenario: Denied when user lacks the required privilege
    Given the given User exists:
      | name      | email            | passwordHash |
      | plainUser | plain@test.com   | hash123      |
    And the caller has a token for that user with privileges "read" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/admin" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 403

  Scenario: OR semantics: any one of multiple listed privileges is sufficient
    Given the given User exists:
      | name       | email           | passwordHash |
      | orUser     | or@test.com     | hash123      |
    And the caller has a token for that user with privileges "manager" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/admin" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200

  Scenario: Path without a gate is accessible with any valid token
    Given the given User exists:
      | name      | email           | passwordHash |
      | anyUser   | any@test.com    | hash123      |
    And the caller has a token for that user with privileges "read" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/content" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200

  Scenario: Method-specific gate applies only to the configured method
    Given the given User exists:
      | name        | email              | passwordHash |
      | methodUser  | method@test.com    | hash123      |
    And the caller has a token for that user with privileges "read" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/reports" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 403

  Scenario: Method-specific gate does not apply to other methods
    Given the given User exists:
      | name        | email               | passwordHash |
      | methodUser2 | method2@test.com    | hash123      |
    And the caller has a token for that user with privileges "read" and claim "tokenThingy" = "true"
    When the POST "/privilege-gated/reports" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200

  Scenario: AND semantics: denied when user satisfies one gate but not the other
    Given the given User exists:
      | name     | email          | passwordHash |
      | andUser  | and@test.com   | hash123      |
    And the caller has a token for that user with privileges "admin" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/dual" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 403

  Scenario: AND semantics: allowed when user satisfies all gates
    Given the given User exists:
      | name      | email           | passwordHash |
      | fullUser  | full@test.com   | hash123      |
    And the caller has a token for that user with privileges "admin finance" and claim "tokenThingy" = "true"
    When the GET "/privilege-gated/dual" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
