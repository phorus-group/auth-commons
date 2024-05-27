package group.phorus.auth.commons.bdd.app.model

import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "devices",
    uniqueConstraints = [UniqueConstraint(columnNames = ["name", "user_id" ])]
)
class Device(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID = UUID.randomUUID(),

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var name: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var disabled: Boolean = false,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var accessTokenJTI: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var refreshTokenJTI: String? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: User? = null,
)

