package group.phorus.auth.commons.context

import group.phorus.auth.commons.dtos.AuthContextData

object AuthContext {
    val context: ThreadLocal<AuthContextData> = ThreadLocal()
}