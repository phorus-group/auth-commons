package group.phorus.auth.commons.context

import group.phorus.auth.commons.dtos.HTTPContextData

object HTTPContext {
    val context: ThreadLocal<HTTPContextData> = ThreadLocal()
}