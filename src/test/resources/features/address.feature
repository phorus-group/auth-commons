Feature: Address CRUD operations
  The CrudController and CrudService should be able to handle all the basic requests made to the test API

  Background:
    Given the caller has the given User:
      | name     | email           | password |
      | testUser | test2@email.com | testPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email           | password | device | expires |
      | test2@email.com | testPass | phone1 | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse
    When the GET "/user" endpoint is called:
      | type   | key                | value                 |
      | header | Authorization      | Bearer {accessToken}  |
    Then the service returns HTTP 200
    And the service returns the User:
      | name     | email           |
      | testUser | test2@email.com |

  Scenario: Caller wants to get an already existing Address by ID
    Given the given Address exists:
      | address     |
      | testAddress |
    When the GET "/address/{addressId}" endpoint is called:
      | type   | key                | value                 |
      | header | Authorization      | Bearer {accessToken}  |
    Then the service returns HTTP 200
    And the service returns the Address

#  Scenario: Caller wants to get an already existing Address by ID
#    Given the given User exists:
#      | name     | email               | passwordHash     |
#      | test     | test2@email.com     | testPassword     |
#    # This next step uses the "userId" saved in the baseScenarioScope, so it'll create
#    # an Address for the new User instead of one for the user currently logged in
#    Given the given Address exists:
#      | address     |
#      | testAddress |
#    When the GET "/address/{addressId}" endpoint is called:
#      | type   | key                | value                 |
#      | header | Authorization      | Bearer {accessToken}  |
#    Then the service returns HTTP 404