package group.phorus.auth.commons.bdd.app.model

import jakarta.persistence.*
import java.util.*

@Entity
@Table(name = "users")
class User(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var name: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false, unique = true)
    var email: String? = null,

    @Basic(fetch = FetchType.LAZY)
    @Column(nullable = false)
    var passwordHash: String? = null,

    @OneToMany(mappedBy = "user", cascade = [CascadeType.REMOVE])
    var devices: MutableSet<Device> = mutableSetOf(),
)

