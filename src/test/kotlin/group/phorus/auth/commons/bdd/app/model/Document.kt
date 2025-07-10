package group.phorus.auth.commons.bdd.app.model

import group.phorus.auth.commons.authorization.Authorization
import group.phorus.auth.commons.authorization.Authorize
import group.phorus.auth.commons.authorization.AuthorizationMode
import group.phorus.auth.commons.authorization.Operation
import group.phorus.auth.commons.authorization.handler.rest.RESTHandler
import group.phorus.auth.commons.authorization.handler.rest.HTTPMethod
import group.phorus.auth.commons.bdd.app.authorization.DatabasePermissionHandler
import group.phorus.auth.commons.bdd.app.authorization.ValidationHandler
import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "documents")
// Owner-based authorization for all operations
@Authorization(definitions = [
    Authorize(value = "ownerId", matches = ["auth::userId"])
])
// Admin override with highest priority
@Authorization(
    priority = 100,
    definitions = [Authorize(matches = ["auth::privileges/admin"])]
)
// Manager override with medium priority (for testing multiple annotations)
@Authorization(
    priority = 50,
    definitions = [Authorize(matches = ["auth::privileges/manager"])]
)
class Document(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var title: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var content: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var ownerId: UUID? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var departmentId: String? = null,

    // AND mode authorization - requires both privilege and department match
    @Authorization(
        mode = AuthorizationMode.AND,
        definitions = [
            Authorize(matches = ["auth::privileges/finance:read"]),
            Authorize(value = "departmentId", matches = ["auth::properties/department"])
        ]
    )
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var financialData: String? = null,

    // Field-level authorization - only owner or admin can see sensitive content
    @Authorization(definitions = [
        Authorize(value = "ownerId", matches = ["auth::userId"]),
        Authorize(matches = ["auth::privileges/admin"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var sensitiveInfo: String? = null,

    // Field-only authorization (no class auth required)
    @Authorization(definitions = [
        Authorize(matches = ["auth::privileges/special:field"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var fieldOnlyData: String? = null,

    // READ-only field
    @Authorization(
        operations = [Operation.READ],
        definitions = [Authorize(matches = ["auth::privileges/read:documents"])]
    )
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var readOnlyField: String? = null,

    // UPDATE-only field
    @Authorization(
        operations = [Operation.UPDATE],
        definitions = [Authorize(matches = ["auth::privileges/update:documents"])]
    )
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var updateOnlyField: String? = null,

    // Multiple field annotations with different priorities
    @Authorization(
        priority = 100,
        definitions = [Authorize(matches = ["auth::privileges/admin"])]
    )
    @Authorization(
        priority = 50,
        definitions = [Authorize(matches = ["auth::privileges/manager"])]
    )
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var multiAuthField: String? = null,

    // Context resolution tests
    @Authorization(definitions = [
        Authorize(value = "auth::userId", matches = ["::ownerId"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var authContextField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "httpRequest::method", matches = ["GET"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var httpContextField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "::title", matches = ["Context Doc"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var entityContextField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "templateField", matches = ["\${auth::userId}-data"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var templateField: String? = null,

    // Value and matches logic tests
    @Authorization(definitions = [
        Authorize(value = "auth::privileges/test", matches = ["admin", "manager"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var valueMatchField: String? = null,

    @Authorization(definitions = [
        Authorize(matches = ["auth::privileges/exists"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var onlyMatchField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "auth::privileges")
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var onlyValueField: String? = null,

    // REST handler tests
    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/permissions/get/\${::id}/\${auth::userId}",
                method = HTTPMethod.GET,
                forwardAuth = true,
                saveTo = "getHandler"
            ),
            value = "getHandler::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var getHandlerField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/permissions/post/\${::id}/\${auth::userId}",
                method = HTTPMethod.POST,
                forwardAuth = true,
                saveTo = "postHandler"
            ),
            value = "postHandler::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var postHandlerField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/permissions/noauth/\${::id}",
                method = HTTPMethod.GET,
                forwardAuth = false,
                saveTo = "noAuth"
            ),
            value = "noAuth::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var noAuthField: String? = null,

    // REST handler error scenarios
    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/slow/\${::id}",
                method = HTTPMethod.GET,
                saveTo = "timeout"
            ),
            value = "timeout::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var timeoutField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/error/\${::id}",
                method = HTTPMethod.GET,
                saveTo = "networkError"
            ),
            value = "networkError::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var networkErrorField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://invalid-url/\${invalid::reference}",
                method = HTTPMethod.GET,
                saveTo = "invalidUrl"
            ),
            value = "invalidUrl::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var invalidUrlField: String? = null,

    // Custom handler tests
    @Authorization(definitions = [
        Authorize(
            handler = DatabasePermissionHandler::class,
            handlerConfig = "{\"userId\": \"\${auth::userId}\", \"resourceId\": \"\${::id}\", \"resourceType\": \"document\"}",
            value = "dbPermissions::hasAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var databaseField: String? = null,

    @Authorization(definitions = [
        Authorize(
            handler = ValidationHandler::class,
            handlerConfig = "{\"validationType\": \"rulesBased\", \"threshold\": 75, \"rules\": [\"privilege:admin\", \"privilege:validation:access\"]}",
            value = "validation::isValid",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var validationField: String? = null,

    // Handler chaining
    @Authorization(definitions = [
        Authorize(
            handler = DatabasePermissionHandler::class,
            handlerConfig = "{\"userId\": \"\${auth::userId}\", \"resourceId\": \"\${::id}\", \"resourceType\": \"document\", \"saveTo\": \"dbCheck\"}"
        ),
        Authorize(
            handler = ValidationHandler::class,
            handlerConfig = "{\"validationType\": \"complex\", \"threshold\": 66}",
            value = "validation::isValid",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var chainedField: String? = null,

    // REST handler authorization - external validation
    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/permissions/document/\${::id}/user/\${auth::userId}",
                method = HTTPMethod.GET,
                forwardAuth = true,
                saveTo = "permissions"
            ),
            value = "permissions::canAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var restrictedData: String? = null,

    // Template and context edge cases
    @Authorization(definitions = [
        Authorize(value = "\${auth::userId}", matches = ["\${::ownerId}"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var validTemplateField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "\${invalid::context}", matches = ["should-fail"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var invalidTemplateField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "\${auth::properties/nested/\${::id}/value}", matches = ["nested-test"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var nestedTemplateField: String? = null,

    // Organization context tests
    @Authorization(definitions = [
        Authorize(matches = ["org::permissions/documents/read"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var orgDataField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "org::organizationId", matches = ["\${auth::properties/organizationId}"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var orgPermissionField: String? = null,

    @Authorization(definitions = [
        Authorize(matches = ["org::roles/manager", "org::roles/admin"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var orgRoleField: String? = null,

    // Handler context tests
    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/setup/\${::id}",
                saveTo = "setup"
            )
            // No value/matches = setup step only
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var setupField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/response/\${::id}",
                saveTo = "responseTest"
            ),
            value = "response::data",
            matches = ["allowed"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var responseField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/handler/\${::id}"
                // Uses default saveTo = "handler"
            ),
            value = "handler::result",
            matches = ["success"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var handlerField: String? = null,

    // Invalid context references
    @Authorization(definitions = [
        Authorize(matches = ["nonexistent::context/field"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var invalidContextField: String? = null,

    @Authorization(definitions = [
        Authorize(value = "::missingProperty", matches = ["should-not-match"])
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var missingFieldRef: String? = null,

    // Error handling and edge case fields
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var nullField: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var circularRefField: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var deepNestedField: String? = null,

    @Authorization(definitions = [
        Authorize(
            handler = ValidationHandler::class,
            handlerConfig = "{\"validationType\": \"error\", \"throwException\": true}",
            value = "validation::isValid",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var errorHandlerField: String? = null,

    @Authorization(definitions = [
        Authorize(
            handler = DatabasePermissionHandler::class,
            handlerConfig = "{\"userId\": \"\${auth::userId}\", \"resourceId\": \"\${::id}\", \"resourceType\": \"document\", \"saveTo\": \"customSaveTo\"}",
            value = "customSaveTo::hasAccess",
            matches = ["true"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var saveToField: String? = null,

    @Authorization(definitions = [
        Authorize(
            restHandler = RESTHandler(
                call = "http://localhost:8088/api/precedence/\${::id}",
                saveTo = "restPrecedence"
            ),
            value = "restPrecedence::result",
            matches = ["rest-wins"]
        ),
        Authorize(
            handler = ValidationHandler::class,
            handlerConfig = "{\"validationType\": \"precedence\"}",
            value = "validation::result",
            matches = ["handler-wins"]
        )
    ])
    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var precedenceField: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = true)
    var securityField: String? = null
)