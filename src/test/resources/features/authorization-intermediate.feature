Feature: Authorization functionality used to an intermediate level
  # Tests class-level, field-level, modes (AND/OR), operations, and CRUD enforcement
  # Covers: Multiple annotations, priorities, operation filtering, empty authorization

  Background:
    Given the caller has the given User:
      | name        | email                | password |
      | coreTestUser| coretest@email.com   | testPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email              | password | device     | expires |
      | coretest@email.com | testPass | coreDevice | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse

  Scenario: Multiple authorization annotations with priority ordering
    # Tests multiple @Authorization annotations with OR logic and priority ordering
    # Higher priority checked first, then code order - admin bypass overrides owner check
    Given the caller is not owner but has admin privilege
    And the given Document exists with multiple authorization levels:
      | title           | content           | ownerId          |
      | Priority Doc    | Priority content  | {differentUser}  |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    # Admin annotation (priority 100) grants access despite not being owner

  Scenario: AND mode requires all conditions to pass
    # Tests AuthorizationMode.AND where ALL definitions must pass
    # User needs finance privilege AND matching department
    Given the caller has finance privilege and department
    And the given Document exists with financial data:
      | title           | content           | departmentId | financialData        |
      | AND Mode Doc    | AND content       | finance      | confidential numbers |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the financial data should be accessible

  Scenario: AND mode fails when one condition fails
    # Tests AuthorizationMode.AND failure when department doesn't match
    Given the caller has finance privilege but wrong department
    And the given Document exists with financial data:
      | title           | content           | departmentId | financialData     |
      | Wrong Dept Doc  | Wrong content     | hr           | salary information |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the financial data should not be accessible

  Scenario: Field-level authorization inheritance and restrictions
    # Tests field inheritance (class + field rules) and field-only authorization
    Given the caller owns document but lacks field privilege
    And the given Document exists with field authorization:
      | title           | content           | sensitiveInfo    | fieldOnlyData    |
      | Field Doc       | Field content     | inherited secret | field only secret |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the sensitive info should be accessible
    And the field only data should not be accessible

  Scenario: Operation-specific authorization
    # Tests operations=[Operation.READ] vs operations=[Operation.UPDATE] vs Operation.ALL
    Given the caller has read-only privileges
    And the given Document exists for operation testing:
      | title           | content           | readOnlyField    | updateOnlyField  |
      | Operation Doc   | Operation content | read data        | update data      |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the read only field should be accessible
    And the update only field should not be accessible

  Scenario: Operation-specific authorization blocks UPDATE
    # Tests UPDATE operation blocked when user only has READ privileges
    Given the caller has read-only privileges
    And the given Document exists for operation testing:
      | title           | content           |
      | Update Test     | Update content    |
    And the caller has the given Document for update:
      | title           | content           |
      | Updated Title   | Updated content   |
    When the PUT "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 403

  Scenario: Empty authorization allows unrestricted access
    # Tests entity with no @Authorization annotations - should allow all access
    Given the caller has minimal privileges
    And the given Address exists with no authorization:
      | address           |
      | 123 Open Street   |
    When the GET "/address/{addressId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    # No @Authorization = no restrictions

  Scenario: Multiple field annotations with OR logic and priority
    # Tests multiple @Authorization on same field with OR logic and priority ordering
    Given the caller has manager role but not admin
    And the given Document exists with multiple field annotations:
      | title           | content           | multiAuthField   |
      | Multi Field     | Multi content     | manager data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And the multi auth field should be accessible

  Scenario: CREATE operation with field authorization
    # Tests CREATE operation requiring both class and field authorization
    Given the caller has create privileges and field access
    And the caller has the given Document for creation:
      | title           | content           | sensitiveInfo    |
      | Create Test     | Create content    | create secret    |
    When the POST "/document" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 201

  Scenario: DELETE operation with authorization
    # Tests DELETE operation authorization enforcement
    Given the caller has delete privileges
    And the given Document exists for deletion:
      | title           | content           |
      | Delete Test     | Delete content    |
    When the DELETE "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 204

  Scenario: Empty definitions always pass
    # Tests @Authorization with empty definitions array - should always grant access
    Given the caller has no special privileges
    And the given Document exists with empty definitions:
      | title           | content           |
      | Empty Auth      | Empty content     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200