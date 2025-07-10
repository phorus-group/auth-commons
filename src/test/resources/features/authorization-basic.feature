Feature: Basic authorization operations
  # Tests core authorization functionality, class-level, field-level, modes (AND/OR), operations, and CRUD enforcement
  # Covers: Multiple annotations, priorities, operation filtering, empty authorization, basic REST handlers

  Background:
    Given the caller has the given User:
      | name        | email                | password |
      | authTestUser| authtest@email.com   | testPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email                | password | device       | expires |
      | authtest@email.com   | testPass | authTestBg   | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the User:
      | name        | email                |
      | authTestUser| authtest@email.com   |

  Scenario: User can access their own document (admin privilege)
    Given the given Document exists:
      | title         | content        | sensitiveInfo |
      | Own Doc       | Own content    | secret data   |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document with accessible fields

  Scenario: User can create document they own
    Given the caller has the given Document:
      | title         | content        |
      | New Doc       | New content    |
    When the POST "/document" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 201

  Scenario: User can update their own document
    Given the given Document exists:
      | title         | content        |
      | Update Doc    | Update content |
    And the caller has the given Document:
      | title           | content          |
      | Updated Title   | Updated content  |
    When the PUT "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document

  Scenario: User can delete their own document
    Given the given Document exists:
      | title         | content        |
      | Delete Doc    | Delete content |
    When the DELETE "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 204

  Scenario: Field-level authorization - sensitive info accessible by owner
    Given the given Document exists:
      | title         | content        | sensitiveInfo    |
      | Field Doc     | Field content  | very secret data |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document with accessible fields

  Scenario: REST handler authorization grants access when external service approves
    Given the given Document exists:
      | title           | content           | restrictedData    |
      | REST Handler Doc| REST content      | classified info   |
    And the external permission service allows access for document "documentId"
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document with restricted data

  Scenario: REST handler authorization denies access when external service rejects
    Given the given Document exists:
      | title           | content           | restrictedData      |
      | Denied Doc      | Denied content    | top secret info     |
    And the external permission service denies access for document "documentId"
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document without restricted data

  Scenario: REST handler authorization fails gracefully when external service is unavailable
    Given the given Document exists:
      | title           | content           | restrictedData    |
      | Unavailable Doc | Unavailable       | secret info       |
    And the external permission service is unavailable
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Document without restricted data

  Scenario: User can access their own address
    Given the given Address exists:
      | address           |
      | 123 Main Street   |
    When the GET "/address/{addressId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the service returns the Address