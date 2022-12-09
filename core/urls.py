
from django.urls import include, path

from .views import LoginApiView, LogoutAPIView, ProfileInfoAPIView, ProfilePasswordAPIView, RegisterApiView, UserAPIView, UsersAPIView


urlpatterns = [
    path("register", RegisterApiView.as_view() ),
    path("login", LoginApiView.as_view() ),
    path("user/<str:scope>", UserAPIView.as_view()),
    path("users/info", ProfileInfoAPIView.as_view()),
    path("users/password", ProfilePasswordAPIView.as_view()),
    path("logout", LogoutAPIView.as_view()),
    path("users/", UsersAPIView.as_view()),
    path("users/<str:pk>", UsersAPIView.as_view()),
]