from flask_restx import marshal, reqparse


def paginate_query(query, model, page=1, per_page=10):
    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    return {
        "items": [marshal(item, model) for item in pagination.items],
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    }


pagination_parser = reqparse.RequestParser()
pagination_parser.add_argument("page", type=int, default=1, location="args")
pagination_parser.add_argument("per_page", type=int, default=10, location="args")
