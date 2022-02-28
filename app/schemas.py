from app.models import User, Article, Comment
from . import ma
from marshmallow import fields

from marshmallow.validate import Length, Range

class UserSchema(ma.Schema):
    class Meta:
        model = User
        fields = ("user_id", "username" )

user_schema = UserSchema()
users_schema = UserSchema(many=True)


class ArticleSchema(ma.Schema):
    title = fields.Str(required=True, validate=Length(min=4))

    class Meta:
        model = Article
        fields = ("title", "content", "date", "u_id", )

article_schema = ArticleSchema()
articles_schema = ArticleSchema(many=True)


class CommentSchema(ma.Schema):
    class Meta:
        model = Comment
        fields = ("user_id", "article_id", "description")
        
comment_schema = CommentSchema()
comments_schema = CommentSchema(many=True)
