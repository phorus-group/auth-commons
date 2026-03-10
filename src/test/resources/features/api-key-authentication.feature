@apikey
Feature: API key authentication
  The API key filter validates requests using a static API key from configuration

  Scenario: Valid API key passes and populates context
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | test-default-key   |
    Then the service returns HTTP 200
    And the response contains keyId "default"

  Scenario: Named partner API key passes and resolves identity
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | partner-a-secret   |
    Then the service returns HTTP 200
    And the response contains keyId "partner-a"

  Scenario: Missing API key returns 401
    When the GET "/api-key-protected/identity" endpoint is called
    Then the service returns HTTP 401

  Scenario: Invalid API key returns 401
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value           |
      | header | X-API-KEY | wrong-key       |
    Then the service returns HTTP 401

  Scenario: Ignored path bypasses API key check
    When the GET "/api-key-ignored/public" endpoint is called
    Then the service returns HTTP 200
