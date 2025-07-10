package group.phorus.auth.commons.bdd.app.model

import group.phorus.auth.commons.authorization.Authorization
import group.phorus.auth.commons.authorization.Authorize
import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "addresses")
// Owner-based authorization - user can only access their own addresses
@Authorization(definitions = [
    Authorize(value = "user/id", matches = ["auth::userId"])
])
class Address(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var address: String? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: User? = null,
)