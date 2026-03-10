@apikey @apikey-protected-paths
Feature: API key protected paths
  When protected-paths is configured instead of ignored-paths, only the listed
  paths require API key authentication. Everything else is skipped.

  Scenario: Protected path requires API key
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | test-default-key   |
    Then the service returns HTTP 200
    And the response contains keyId "default"

  Scenario: Protected path rejects missing API key
    When the GET "/api-key-protected/identity" endpoint is called
    Then the service returns HTTP 401

  Scenario: Non-protected path bypasses API key check
    When the GET "/api-key-ignored/public" endpoint is called
    Then the service returns HTTP 200
