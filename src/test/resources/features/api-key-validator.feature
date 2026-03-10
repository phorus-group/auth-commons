@apikey
Feature: Custom API key validator
  The API key filter can delegate validation to a custom ApiKeyValidator bean

  Scenario: Valid dynamic key passes validator and populates context with metadata
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value           |
      | header | X-API-KEY | dynamic-key-123 |
    Then the service returns HTTP 200
    And the response contains keyId "dynamic-partner"
    And the response contains metadata key "partnerId" with value "partner-dynamic"
    And the response contains metadata key "tier" with value "premium"

  Scenario: Another valid dynamic key passes with different metadata
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value            |
      | header | X-API-KEY | webhook-key-456  |
    Then the service returns HTTP 200
    And the response contains keyId "webhook-service"
    And the response contains metadata key "service" with value "webhooks"
    And the response contains metadata key "environment" with value "test"

  Scenario: Invalid dynamic key is rejected by validator
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value               |
      | header | X-API-KEY | unknown-dynamic-key |
    Then the service returns HTTP 401

  Scenario: Static key takes precedence over validator
    When the GET "/api-key-protected/identity" endpoint is called:
      | type   | key       | value              |
      | header | X-API-KEY | test-default-key   |
    Then the service returns HTTP 200
    And the response contains keyId "default"
    And the response does not contain metadata key "partnerId"
