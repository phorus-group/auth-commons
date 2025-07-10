Feature: Authorization edge cases
  # Tests error handling, performance, security, configuration, and system integration
  # Covers: missing auth, malformed configs, concurrency, memory, transactions, lazy loading

  Background:
    Given the caller has the given User:
      | name         | email                | password |
      | edgeTestUser | edgetest@email.com   | testPass |
    And the POST "/user" endpoint is called
    And the caller has the given login information:
      | email              | password | device     | expires |
      | edgetest@email.com | testPass | edgeDevice | false   |
    And the POST "/auth/login" endpoint is called
    And the service returns HTTP 200
    And the service returns the AuthResponse

  Scenario: Missing authentication context and malformed configurations
    # Tests missing auth context, malformed annotations, invalid configurations
    Given the authentication context is cleared
    And the given Document exists with malformed authorization:
      | title           | content           |
      | Malformed Auth  | Malformed content |
    When the GET "/document/{documentId}" endpoint is called
    Then the service returns HTTP 401
    # Missing auth context properly handled

  Scenario: Null field access and circular references
    # Tests null entity fields, circular reference handling, deep nesting
    Given the caller has standard access
    And the given Document exists with null fields and circular refs:
      | title           | content           | nullField | circularRefField | deepNestedField  |
      | Null Fields     | Null content      | null      | circular         | deep.nested.data |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the service returns HTTP 200
    And null fields should be handled gracefully
    And circular references should not cause infinite loops
    And deep nesting should complete within time limits

  Scenario: Database errors and transaction handling
    # Tests database failures, transaction rollback, authorization within transactions
    Given the database has intermittent failures
    And the caller has transactional document creation setup
    And the caller has the given Document for transactional create:
      | title           | content           |
      | Transaction Doc | Transaction test  |
    When the POST "/document" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then the transaction should handle authorization failures properly
    And no partial data should remain in database

  Scenario: Concurrent authorization and thread safety
    # Tests concurrent access, race conditions, thread safety
    Given the given Document exists for concurrency testing:
      | title           | content           |
      | Concurrent Doc  | Concurrent test   |
    When multiple concurrent authorization checks are performed:
      | threadCount | requestCount |
      | 10          | 50           |
    Then all authorization checks should complete successfully
    And no race conditions should occur
    And context isolation should be maintained

  Scenario: Memory usage and performance with large datasets
    # Tests memory efficiency, performance impact, large entity handling
    Given multiple documents exist for performance testing:
      | count | titlePrefix  | contentPrefix   |
      | 100   | Perf Doc     | Perf content    |
    When authorization checks are performed on all documents
    Then memory usage should remain within acceptable limits
    And authorization should complete within performance targets
    And no memory leaks should occur

  Scenario: Configuration validation and handler timeouts
    # Tests handler timeout, retry logic, cache configuration, interceptor toggle
    Given handler configuration has custom settings:
      | timeoutMs | retryAttempts | cacheEnabled | cacheTtlSeconds |
      | 1000      | 2             | true         | 60              |
    And the external service has slow responses:
      | delayMs |
      | 1500    |
    And the given Document exists for timeout testing:
      | title           | content           | timeoutField     |
      | Timeout Test    | Timeout content   | timeout data     |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then timeout configuration should be respected
    And retry logic should be applied
    And cache behavior should work correctly

  Scenario: Lazy loading and JPA relationship authorization
    # Tests lazy loading compatibility, @OneToMany/@ManyToMany authorization
    Given lazy loading is enabled for relationships
    And the given Address exists with lazy loaded user relationship:
      | address           | userRelationField |
      | 123 Lazy Street   | lazy user data    |
    When the GET "/address/{addressId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then lazy loading should work correctly with authorization
    And relationship authorization should be enforced
    And no lazy initialization errors should occur

  Scenario: Bulk operations bypass and direct SQL
    # Tests @Query @Modifying bypass, direct SQL bypass, performance impact
    Given multiple documents exist in database:
      | count |
      | 20    |
    When bulk operations are performed bypassing authorization:
      | operationType | queryType |
      | UPDATE        | @Modifying |
      | DELETE        | direct SQL |
    Then bulk operations should bypass authorization as expected
    And warnings should be logged about bypassed authorization
    And direct SQL should not trigger authorization

  Scenario: Security edge cases and privilege escalation
    # Tests privilege escalation, context injection, template injection, memory leaks
    Given the caller has potential security attack vectors:
      | attackType        | payload                    |
      | contextInjection  | malicious context data     |
      | templateInjection | ${malicious::expression}   |
      | privilegeEscalation| crafted privilege strings |
    And the given Document exists with security test fields:
      | title           | content           | securityField    |
      | Security Test   | Security content  | security data    |
    When the GET "/document/{documentId}" endpoint is called:
      | type   | key           | value                |
      | header | Authorization | Bearer {accessToken} |
    Then security attacks should be prevented
    And context should be properly sanitized
    And privilege escalation should be blocked
    And memory should be cleaned up properly

  Scenario: Authorization interceptor toggle and caching
    # Tests enable/disable interceptor, cache behavior, context cleanup
    Given authorization interceptor settings are tested:
      | interceptorEnabled | cacheEnabled | maxCacheSize |
      | true              | true         | 50           |
    And the given Document exists for interceptor testing:
      | title           | content           |
      | Interceptor Doc | Interceptor test  |
    When authorization interceptor behavior is verified
    Then interceptor should enforce authorization when enabled
    And cache should respect size limits
    And context should be cleaned up after requests
    And no context data should leak between requests

  Scenario: Invalid context providers and provider priority
    # Tests invalid context provider config, provider priority resolution
    Given context providers have priority conflicts and invalid configs:
      | providerName | priority | isValid |
      | orgProvider  | 75       | true    |
      | testProvider | 75       | false   |
      | highProvider | 100      | true    |
    When context resolution is performed with conflicting providers
    Then invalid providers should be handled gracefully
    And highest priority valid provider should be used
    And provider errors should not break authorization