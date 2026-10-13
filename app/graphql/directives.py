from functools import wraps

from ariadne import SchemaDirectiveVisitor
from graphql import GraphQLError, default_field_resolver

#проверка прав 
class IsAuthenticatedDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        original = field.resolve or default_field_resolver

        @wraps(original)
        def wrapper(obj, info, **kwargs):
            if not info.context.get("user"):
                raise GraphQLError("Authentication required")

            return original(obj, info, **kwargs)

        field.resolve = wrapper
        return field


class IsAdminDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        original = field.resolve or default_field_resolver

        @wraps(original)
        def wrapper(obj, info, **kwargs):
            user = info.context.get("user")

            if not user:
                raise GraphQLError("Authentication required")

            if not user.is_admin:
                raise GraphQLError("Admin only")

            return original(obj, info, **kwargs)

        field.resolve = wrapper
        return field