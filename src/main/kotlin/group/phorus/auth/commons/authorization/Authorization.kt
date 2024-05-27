package group.phorus.auth.commons.authorization

/**
 * Enum with common data operation.
 */
enum class Operation {
    WRITE, READ, UPDATE, DELETE, ALL
}

/**
 * Annotation used to check if client has authorization to access a specific entity, or entity field.
 * This annotation can be used multiple times in the same entity or field to specify multiple ways of
 * validating the client's authorization.
 *
 * @param operations the operations that will be covered by this [Authorization] definition. Default: [Operation.ALL].
 * @param definitions definitions used to configure the way the client's authorization should be validated.
 */
@Repeatable
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY_GETTER, AnnotationTarget.PROPERTY_SETTER)
annotation class Authorization(
    vararg val definitions: Authorize = [],
    val operations: Array<Operation> = [Operation.ALL],
)