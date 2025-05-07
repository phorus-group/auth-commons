package group.phorus.auth.commons.bdd.app.model

import group.phorus.auth.commons.authorization.Authorization
import group.phorus.auth.commons.authorization.Authorize
import group.phorus.auth.commons.authorization.Operation
import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "addresses")
@Authorization(Authorize(value = "user/id", matches = ["context::userId"])) // This will be used with the object constructor
class Address(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var address: String? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @get:Authorization(operations = [Operation.ALL], definitions = [
        Authorize(value = "id", matches = ["auth::userId"])
    ]) // This allows the operation if the caller is the owner
//    @Authorization(operations = [Operation.READ],  definitions = [
//        Authorize(matches = ["context::privileges/addresses:readAny", "context::privileges/addresses:all"])
//    ]) // This allows the operation if the caller has any of these privileges
//    @Authorization( // This allows the operation if the caller is the owner and has this privilege
//        operations = [Operation.READ],
//        definitions = [
//            Authorize(value = "id", matches = ["context::userId"]),
//            Authorize(matches = ["context::privileges/addresses:read"]),
//        ]
//    )
//    @Authorization(operations = [Operation.READ], definitions = [
//        Authorize(value = "id", handler = Handler(method = HTTPMethod.GET, call = "organization-service::membership/findAllBy/userId", set = "::memberships")),
//        Authorize(value = "::memberships/organization/id", matches = ["context::privileges/organization-\${by}::addresses:read"]),
//    ]) // This allows the operation if the caller has this organization privilege in one of the "organization" the owner is part of
//    @Authorization(operations = [Operation.READ], definitions = [
//        Authorize(value = "id", handler = Handler(call = "organization-service::membership/findAllBy/userId", set = "::memberships"), matches = ["context::privileges/organization-\${::memberships/organization/id}::addresses:read"]),
//    ]) // This allows the operation if the caller has this organization privilege in one of the "organization" the owner is part of, kafka handler may handle generics, or may try to find a bean of itself that accepts the call string
//    @Authorization(operations = [Operation.UPDATE], definitions = [
//        Authorize(value = "id", handler = Handler(call = "organization-service::membership/findAllBy/userId", set = "::memberships"), matches = ["context::privileges/organization-\${::memberships/organization/id}::addresses:read"]),
//    ]) // This allows the operation if the caller has this organization privilege in one of the "organization" the owner is part of, kafka handler may handle generics, or may try to find a bean of itself that accepts the call string
    var user: User? = null,
)