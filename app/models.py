from . import db
from datetime import datetime
from flask_bcrypt import generate_password_hash, check_password_hash


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    content = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now)
    u_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    likes = db.relationship('LikeArticle', backref='article', lazy='dynamic')
    comments = db.relationship('Comment', backref='article', lazy='dynamic')


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.user_id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.user_id'))
)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    articles = db.relationship('Article', backref='author', lazy=True)
    liked = db.relationship('LikeArticle', foreign_keys='LikeArticle.user_id', backref='user', lazy='dynamic')
    comments = db.relationship('Comment', backref='user', lazy=True)
    followed = db.relationship('User',
                               secondary=followers,
                               primaryjoin=(followers.c.follower_id == user_id),
                               secondaryjoin=(followers.c.followed_id == user_id),
                               backref=db.backref('followers', lazy='dynamic'),
                               lazy='dynamic')


    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')
 
    def check_password(self, password):
        return check_password_hash(self.password, password)


class LikeArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))
    description = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Comment('{self.description}')"