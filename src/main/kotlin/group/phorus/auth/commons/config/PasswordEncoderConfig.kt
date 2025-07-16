package group.phorus.auth.commons.config

import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

@AutoConfiguration
class PasswordEncoderConfig {

    /**
     * SCrypt password encoder configuration for production use.
     *
     * SCrypt is a memory-hard key derivation function designed to make brute-force attacks expensive.
     * Memory usage formula: ~128 × cpuCost × memoryCost × parallelization bytes
     *
     * Current settings use: ~128 × 16384 × 8 × 1 = ~16MB per password encoding
     *
     * cpuCost (N): 16384 - CPU/memory cost parameter
     *   - Higher values = more secure but slower and more memory-intensive
     *   - Must be power of 2, typical production range: 16384-65536
     *   - 16384 provides strong security while remaining practical
     *   - Takes ~100-200ms per password hash (acceptable for login/registration)
     *
     * memoryCost (r): 8 - Block size parameter
     *   - Standard value providing good memory mixing
     *   - Higher values exponentially increase memory usage
     *   - 8 is recommended for most production systems
     *
     * parallelization (p): 1 - Parallelization parameter
     *   - Single-threaded is standard for web applications
     *   - Higher values would multiply memory usage
     *
     * keyLength: 32 - Length of derived key in bytes
     *   - 32 bytes = 256 bits (cryptographically strong)
     *   - Standard for secure password hashing
     *
     * saltLength: 16 - Length of salt in bytes
     *   - 16 bytes = 128 bits (prevents rainbow table attacks)
     *   - Adequate randomness for production use
     *
     * Security levels:
     * - Conservative: 16384 (current) - Good security, ~16MB memory, ~100-200ms
     * - High security: 32768 - Very secure, ~32MB memory, ~400-800ms
     * - Maximum: 65536 - Extremely secure, ~64MB memory, ~1-2s per hash
     *
     * Note: Consider your server's memory constraints and expected concurrent users
     * when choosing parameters. Each concurrent password operation uses the full memory amount.
     */
    @Bean
    fun passwordEncoder(): SCryptPasswordEncoder =
        SCryptPasswordEncoder(
            16384,  // cpuCost: Strong production security
            8,   // memoryCost: Standard block size
            1,  // parallelization: Single-threaded
            32,    // keyLength: 256-bit key
            16     // saltLength: 128-bit salt
        )
}