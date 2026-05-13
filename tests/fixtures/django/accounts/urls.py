from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("users", views.UserViewSet, basename="user")
router.register(dynamic_prefix(), views.DynamicViewSet, basename=get_basename())

custom_router = CustomRouter()

urlpatterns = [
    path("", views.index, name="account_index"),
    path("users/<int:pk>/", views.AccountDetailView.as_view(), name="account_detail"),
    path("api/", include(router.urls)),
    path(make_path(), views.dynamic_view, name="dynamic_view"),
]
