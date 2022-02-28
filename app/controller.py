import random
from app.models import User, Article, Comment, LikeArticle, followers
from flask_restplus import Resource
from app import db
from app import api, app
import jwt
from app.decorator import token_required
import datetime as dt
from app.schemas import user_schema, article_schema, articles_schema, comment_schema
from twilio.rest import Client
from flask import request, Response, session
from app.forms import RegistrationForm


class SignupApi(Resource):
    def post(self):
        form = RegistrationForm.from_json(request.json)
        if not form.validate():
            error_message = f"Invalid input params : {form.errors}"
            response = Response(error_message, 400, mimetype='application/json')
            return response
        body = request.get_json()
        user = User(**body)
        users = User.query.all()
        emails = [i.email for i in users]
        if user.email in emails :
            response = Response("email is already taken", 201, mimetype='application/json')
            return response
        user.hash_password()
        db.session.add(user)
        db.session.commit()
        return user_schema.dump(user), 200


class LoginApi(Resource):
    def post(self):
        body = request.get_json()
        user = User.query.filter_by(email=body.get('email')).first()
        authorized = user.check_password(password=body.get('password'))
        token = jwt.encode({'user_id': user.user_id, 'exp': dt.datetime.utcnow() + dt.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        if not authorized:
            return {'error': 'Email or password invalid'}, 401
        return {'token': token.decode('UTF-8')}


# inprocress
class LogoutApi(Resource):
    @token_required
    def post(self,user_id):
        auth_header = request.headers.get('x-access-tokens')
        # print(auth_header)
        # import code; code.interact(local=dict(globals(), **locals()))
        return {'message': 'You successfully logged out'}


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
    def patch(self, user_id):
        user = User.query.filter_by(user_id= self.user_id).first()
        if 'username' in request.json:
            user.username = request.json['username']
        db.session.commit()
        return user_schema.dump(user)


class CreateArticle(Resource):
    @token_required
    def post(self, user_id):
        article = Article(
            title=request.json['title'],
            content=request.json['content'],
            u_id = self.user_id
        )
        db.session.add(article)
        db.session.commit()

        return article_schema.dump(article), {"message": "article created.."}


class ArticleList(Resource):
    @token_required
    def get(self):
        articles = Article.query.all()
        print(articles)
        return articles_schema.dump(articles)


class UpdateArticle(Resource):
    @token_required
    def patch(self, user_id, a_id):
        article = Article.query.filter_by(id=a_id, u_id=self.user_id).first()
        if 'title' in request.json:
            article.title = request.json['title']
        db.session.commit()
        return article_schema.dump(article), {"message": "article title updated.."}


class DeleteArticle(Resource):
    @token_required
    def delete(self, user_id, a_id):
        article = Article.query.filter_by(id=a_id, u_id=self.user_id).first()
        db.session.delete(article)
        db.session.commit()
        return '', 204   


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
            return 'liked'
        elif action == "unlike":
            LikeArticle.query.filter_by(user_id=self.user_id, article_id=article.id).delete()
            db.session.commit()
            return 'unliked'


class AddComment(Resource):
    @token_required
    def post(self, user_id):
        comment = Comment(
            user_id=self.user_id,
            article_id=request.json['article_id'],
            description=request.json['description']
        )
        db.session.add(comment)
        db.session.commit()
        return comment_schema.dump(comment), {"message": "added comment.."}


class RemoveComment(Resource):
    @token_required
    def post(self, user_id, comment_id):
        Comment.query.filter_by(user_id=self.user_id, id=comment_id).delete()
        db.session.commit()
        return "removed"


class FollowUnfollow(Resource):
    @token_required
    def patch(self, user_id, f_id, action):
        user = User.query.filter_by(user_id=f_id).first()
        if action == 'follow': 
            if user is None:
                response = Response('User %s not found.' % user, status=404, mimetype='application/json')
            elif user.user_id == self.user_id:
                response = Response('You can\'t follow yourself!', status=404, mimetype='application/json')
            else:
                if self.followed.filter(followers.c.followed_id == user.user_id).count() > 0:
                    response = Response("You are already following "+ user.username, status=200, mimetype='application/json')
                else:
                    follow = followers.insert().values(follower_id = self.user_id,followed_id = user.user_id)
                    db.session.execute(follow)
                    db.session.commit()
                    response = Response("You are now following "+ user.username, status=200, mimetype='application/json')
            return response
        elif action == 'unfollow':
            if user is None:
                response = Response('User %s not found.' % user, status=404, mimetype='application/json')
            elif user.user_id == self.user_id:
                response = Response('You can\'t unfollow yourself!', status=404, mimetype='application/json')
            else:
                if self.followed.filter(followers.c.followed_id == user.user_id).count() > 0:
                    self.followed.remove(user)
                    db.session.commit()
                    response = Response("You unfollowed "+user.username, status=200, mimetype='application/json')
                else:
                    response = Response("You are not following "+user.username, status=200, mimetype='application/json')
            return response


class GetOTP(Resource):
    def post(self): 
        account_sid = "AC2f608aa8231238e290af762042b4a1d7"
        auth_token = "962fc0a3453ead25749e1477536f4d0a"
        otp = random.randrange(100000,999999)
        session['response'] = otp
        print(otp)
        client = Client(account_sid, auth_token)
        number = request.json['number']
        message = client.messages.create(
            body = "Your OTP is "+str(otp),
            from_ = '+19378872764',
            to = number
        )
        if message.sid:
            response = Response("otp sent to "+number, status=200, mimetype='application/json')
            return response
        else:
            response = Response("Error in sending OTP to "+number, status=200, mimetype='application/json')
            return response


class VerifyOTP(Resource):
    def post(self):
        otp = request.json.get('otp')
        # import code; code.interact(local=dict(globals(), **locals()))
        
        if "response" in session:
            s = session['response']
            session.pop('response', None)
            # import code; code.interact(local=dict(globals(), **locals()))
            if str(s) == otp:
                response = Response("You are authorise", status=200, mimetype='application/json')
                return response
            else:
                response = Response("You are not authorised", status=200, mimetype='application/json')
                return response
        response = Response("OTP expired or not generated", status=200, mimetype='application/json')
        return response
