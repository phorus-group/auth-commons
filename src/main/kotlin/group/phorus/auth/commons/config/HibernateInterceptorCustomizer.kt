package group.phorus.auth.commons.config

import group.phorus.auth.commons.authorization.interceptor.AuthorizationHibernateInterceptor
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer

@AutoConfiguration
@ConditionalOnProperty(prefix = "group.phorus.authorization.interceptor", name = ["enable"], havingValue = "true", matchIfMissing = true)
class HibernateInterceptorCustomizer(
    private val interceptor: AuthorizationHibernateInterceptor,
) : HibernatePropertiesCustomizer {
    override fun customize(hibernateProperties: MutableMap<String?, Any?>) {
        hibernateProperties.put("hibernate.session_factory.interceptor", interceptor)
    }
}