Feature: Advanced authorization features
  # Tests context resolution, value/matches logic, REST handlers, custom handlers, templates
  # Covers: auth::, httpRequest::, entity:: contexts, handler chaining, template resolution

  Background:
    Given the caller has the given User:
      | name           | email                    | password |
      | advancedTestUser| advancedtest@email.com  | testPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email                   | password | device         | expires |
      | advancedtest@email.com  | testPass | advancedDevice | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse

  Scenario: Context resolution and template variables
    # Tests auth::userId, httpRequest::method, entity::field, template resolution ${auth::userId}
    Given the caller has context setup with organization data
    And the given Document exists with context fields:
      | title           | content           | authContextField | httpContextField | entityContextField | templateField    |
      | Context Doc     | Context content   | auth data        | http data        | entity data        | template data    |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And all context fields should be accessible

  Scenario: Value and matches logic combinations
    # Tests value+matches, only matches, only value, literal vs context matches
    Given the caller has varied privilege levels
    And the given Document exists with value matches tests:
      | title           | content           | valueMatchField  | onlyMatchField   | onlyValueField   |
      | Value Test      | Value content     | match test       | exists test      | truthy test      |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the value match field should be accessible
    And the only match field should be accessible
    And the only value field should be accessible

  Scenario: REST handler with different HTTP methods and auth forwarding
    # Tests GET/POST/PUT/DELETE methods, forwardAuth true/false, timeout handling
    Given the external service supports all HTTP methods
    And the given Document exists with REST handler fields:
      | title           | content           | getHandlerField  | postHandlerField | noAuthField      |
      | REST Methods    | REST content      | get data         | post data        | no auth data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the GET handler field should be accessible
    And the POST handler field should be accessible
    And the no auth field should be accessible

  Scenario: REST handler error scenarios
    # Tests service unavailable, network errors, timeout handling, invalid URLs
    Given the external service is unreliable
    And the given Document exists with error handling fields:
      | title           | content           | timeoutField     | networkErrorField | invalidUrlField  |
      | Error Handling  | Error content     | timeout data     | network data      | invalid data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the timeout field should not be accessible
    And the network error field should not be accessible
    And the invalid url field should not be accessible

  Scenario: Custom handler execution and chaining
    # Tests DatabasePermissionHandler, ValidationHandler, handler chaining, JSON config
    Given the caller has database and validation setup
    And the given Document exists with custom handler fields:
      | title           | content           | databaseField    | validationField  | chainedField     |
      | Custom Handlers | Custom content    | db protected     | validation data  | chained data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the database field should be accessible
    And the validation field should be accessible
    And the chained field should be accessible

  Scenario: Custom handler errors and saveTo contexts
    # Tests custom handler failures, saveTo extraction, handler vs REST precedence
    Given the caller has handler configuration with errors
    And the given Document exists with handler error tests:
      | title           | content           | errorHandlerField | saveToField      | precedenceField  |
      | Handler Errors  | Handler content   | error data        | saveTo data      | precedence data  |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the error handler field should not be accessible
    And the saveTo field should be accessible
    And the precedence field should be accessible

  Scenario: Template resolution edge cases
    # Tests invalid templates, missing context, nested templates, malformed expressions
    Given the caller has template test setup
    And the given Document exists with template edge cases:
      | title           | content           | validTemplateField | invalidTemplateField | nestedTemplateField |
      | Template Edge   | Template content  | valid template     | invalid template     | nested template     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the valid template field should be accessible
    And the invalid template field should not be accessible
    And the nested template field should be accessible

  Scenario: Custom context provider priority and navigation
    # Tests org:: context, priority ordering, deep navigation, context provider priority
    Given the caller has organization context with priority setup
    And the given Document exists with organization context:
      | title           | content           | orgDataField     | orgPermissionField | orgRoleField     |
      | Org Context     | Org content       | org data         | org permission     | org role         |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the org data field should be accessible
    And the org permission field should be accessible
    And the org role field should be accessible

  Scenario: Handler setup steps and response contexts
    # Tests handlers without validation (setup steps), response::, handler::, custom saveTo::
    Given the caller has handler setup without validation
    And the given Document exists with handler contexts:
      | title           | content           | setupField       | responseField    | handlerField     |
      | Handler Context | Handler content   | setup data       | response data    | handler data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the setup field should be accessible
    And the response field should be accessible
    And the handler field should be accessible

  Scenario: Invalid context references and error handling
    # Tests non-existent contexts/fields, malformed context references
    Given the caller has standard privileges
    And the given Document exists with invalid contexts:
      | title           | content           | invalidContextField | missingFieldRef   |
      | Invalid Context | Invalid content   | invalid data        | missing data      |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the invalid context field should not be accessible
    And the missing field ref should not be accessible