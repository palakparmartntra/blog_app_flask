from app.models import User, Article, Comment, LikeArticle
from flask_restplus import Resource
from flask import request
from . import db
from . import api, app
import jwt
from app.decorator import token_required
import datetime as dt
from app.schemas import user_schema, article_schema, articles_schema, comment_schema


@api.route('/signup')
class SignupApi(Resource):
    def post(self):
        body = request.get_json()
        user = User(**body)
        user.hash_password()
        db.session.add(user)
        db.session.commit()
        return user_schema.dump(user), 200

@api.route('/login')
class LoginApi(Resource):

    def post(self):
        body = request.get_json()
        user = User.query.filter_by(email=body.get('email')).first()
        authorized = user.check_password(password=body.get('password'))
        token = jwt.encode({'user_id': user.user_id, 'exp' : dt.datetime.utcnow() + dt.timedelta(minutes=30)}, app.config['SECRET_KEY']) 
        if not authorized:
            return {'error': 'Email or password invalid'}, 401
        return {'token' : token.decode('UTF-8')} 
        

@api.route('/profile')
class UserProfile(Resource):
    @token_required
    def get(self, user_id):
        user = User.query.filter_by(user_id=self.user_id).first()
        if not user:
            response_object = {
            'message': 'not available.sign in first.',
            }
            return response_object, 409
        return user_schema.dump(user)

    @token_required
    def patch(self):
        user = User.query.filter_by(user_id= self.user_id).first()
        if 'username' in request.json:
            user.username = request.json['username']
        db.session.commit()
        return user_schema.dump(user)


@api.route('/create_article')
class CreateArticle(Resource):
    @token_required
    def post(self):
        article = Article(
            title=request.json['title'],
            content=request.json['content'],
            u_id = self.user_id
        )
        db.session.add(article)
        db.session.commit()

        return article_schema.dump(article), {"message": "article created.."}


@api.route('/article_list')
class ArticleList(Resource):
    @token_required
    def get(self):
        articles = Article.query.all()
        print(articles)
        return articles_schema.dump(articles)


@api.route('/update_article/<int:id>')
class UpdateArticle(Resource):
    @token_required
    def patch(self, user_id, id):
        article = Article.query.filter_by(id = id, u_id=self.user_id).first()
        if 'title' in request.json:
            article.title = request.json['title']
        db.session.commit()
        return article_schema.dump(article), {"message": "article title updated.."}

@api.route('/delete_article/<int:id>')
class DeleteArticle(Resource):
    @token_required
    def delete(self,user_id, id):
        article = Article.query.filter_by(id = id, u_id=self.user_id).first()
        db.session.delete(article)
        db.session.commit()
        return '', 204   


@api.route('/like/<int:article_id>/<action>')
class LikeUnlike(Resource):
    @token_required
    def post(self, user_id, article_id, action):
        article = Article.query.filter_by(id=article_id).first()
        
        if action == 'like':
            if LikeArticle.query.filter(LikeArticle.user_id == self.user_id, LikeArticle.article_id == article.id).count() > 0:
                return "already liked"
            like = LikeArticle(user_id=self.user_id, article_id=article.id)
            db.session.add(like)
            db.session.commit()
            return 'likeedd'
        elif action == "unlike":
            LikeArticle.query.filter_by(user_id=self.user_id, article_id=article.id).delete()
            db.session.commit()
            return 'unliked'


@api.route('/add_comment')
class AddComment(Resource):
    @token_required
    def post(self, user_id):
        comment = Comment(
            user_id = self.user_id,
            article_id = request.json['article_id'],
            description = request.json['description']
        )
        db.session.add(comment)
        db.session.commit()
        return comment_schema.dump(comment), {"message": "added comment.."}

@api.route('/comment/<int:comment_id>')
class RemoveComment(Resource):
    @token_required
    def post(self, user_id, comment_id):
        Comment.query.filter_by(user_id=self.user_id, id=comment_id).delete()
        db.session.commit()
        return "removed"


# # ------- follow / unfollowed.

# @api.route('/follow/<int:id>')
# class Follow(Resource):
#     @token_required
#     def patch(self, user_id, id):
#         print(self.user_id)
#         user =  User.query.filter_by(user_id=id).first()
#         print(user.user_id)
#         follow = followers(
#             follower_id = self.user_id,
#             followed_id = user.user_id
#         )
#         db.session.append(follow)
#         db.session.commit()
#         return "followedd"

