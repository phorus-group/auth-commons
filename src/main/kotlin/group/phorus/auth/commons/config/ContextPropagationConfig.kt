// Deprecated: Shouldn't be needed anymore
//
//package group.phorus.auth.commons.config
//
//import group.phorus.auth.commons.context.AuthContext
//import group.phorus.auth.commons.context.HTTPContext
//import group.phorus.auth.commons.dtos.AuthContextData
//import group.phorus.auth.commons.dtos.HTTPContextData
//import io.micrometer.context.ContextRegistry
//import jakarta.annotation.PostConstruct
//import org.springframework.context.annotation.Configuration
//import reactor.core.publisher.Hooks
//
//@Configuration
//class ContextPropagationConfig {
//
//    @PostConstruct
//    fun enableContextPropagation() {
//        Hooks.enableAutomaticContextPropagation()
//
//        // Register AuthContext
//        ContextRegistry.getInstance().registerThreadLocalAccessor(
//            "AUTH_CONTEXT",
//            { AuthContext.context.get() },
//            { AuthContext.context.set(it as AuthContextData) },
//            { AuthContext.context.remove() }
//        )
//
//        // Register requestId
//        ContextRegistry.getInstance().registerThreadLocalAccessor(
//            "HTTP_CONTEXT",
//            { HTTPContext.context.get() },
//            { HTTPContext.context.set(it as HTTPContextData) },
//            { HTTPContext.context.remove() }
//        )
//    }
//}