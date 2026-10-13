from pathlib import Path

from ariadne import load_schema_from_path, make_executable_schema
from ariadne.asgi import GraphQL

from app.graphql.resolvers import (
    query, mutation, user_type, client_type, audit_type
)
from app.graphql.context import get_context_value
from app.graphql.directives import (
    IsAuthenticatedDirective,
    IsAdminDirective
)


schema_path = Path(__file__).with_name("schema.graphql")

type_defs = load_schema_from_path(str(schema_path))

schema = make_executable_schema(
    type_defs,
    query,
    mutation,
    user_type,
    client_type,
    audit_type,
    directives={
        "isAuthenticated": IsAuthenticatedDirective,
        "isAdmin": IsAdminDirective
    }
)

graphql_app = GraphQL(
    schema,
    context_value=get_context_value,
    debug=True
)