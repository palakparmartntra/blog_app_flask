from app.views import (
                        SignupApi,
                        LoginApi, 
                        UserProfile, 
                        LogoutApi,
                        CreateArticle,
                        ArticleList,
                        UpdateArticle,
                        DeleteArticle,
                        LikeUnlike,
                        AddComment,
                        RemoveComment,
                        FollowUnfollow,
                    )

def initialize_routes(api):
    api.add_resource(SignupApi, '/signup')
    api.add_resource(LoginApi, '/login')
    api.add_resource(UserProfile, '/profile')
    api.add_resource(LogoutApi, '/logout')
    api.add_resource(CreateArticle, '/create_article')
    api.add_resource(ArticleList, '/article_list')
    api.add_resource(UpdateArticle, '/update_article/<int:id>')
    api.add_resource(DeleteArticle, '/delete_article/<int:id>')
    api.add_resource(LikeUnlike, '/<int:article_id>/<action>')
    api.add_resource(AddComment, '/add_comment')
    api.add_resource(RemoveComment, '/comment/<int:comment_id>')
    api.add_resource(FollowUnfollow, '/<action>/<int:id>')