from django.urls import include, path
from rest_framework.routers import DefaultRouter, SimpleRouter

from . import views

router = DefaultRouter()
router.register("users", views.UserViewSet, basename="user")
router.register("readonly", views.ReadOnlyAccountViewSet, basename="readonly")
router.register(dynamic_prefix(), views.DynamicViewSet, basename=get_basename())

custom_router = CustomRouter()
readonly_router = SimpleRouter()
readonly_router.register("audit", views.ReadOnlyAuditViewSet, basename="audit")

urlpatterns = [
    path("", views.index, name="account_index"),
    path("users/<int:pk>/", views.AccountDetailView.as_view(), name="account_detail"),
    path("api/", include(router.urls)),
    path("readonly-api/", include(readonly_router.urls)),
    path(make_path(), views.dynamic_view, name="dynamic_view"),
]


def path(route, view, **kwargs):
    return (route, view, kwargs)


ignored_patterns = [
    path("not-a-django-route/", views.status, name="ignored"),
]
