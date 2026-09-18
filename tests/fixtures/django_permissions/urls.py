from django.urls import include, path
from rest_framework.routers import SimpleRouter
from .views import (
    AliasedView,
    ConcreteWrapped,
    DispatchWrapped,
    PermissionsViewSet,
    SettingsView,
    # Keep the following import in the parenthesized list.
    ordinary_view,
    public_api,
)

router = SimpleRouter()
router.register("items", PermissionsViewSet, basename="item")

urlpatterns = [
    path("api/", include(router.urls)),
    path("settings/", SettingsView.as_view()),
    path("public-api/", public_api),
    path("concrete/", ConcreteWrapped.as_view()),
    path("dispatch/", DispatchWrapped.as_view()),
    path("aliased/", AliasedView.as_view()),
    path("ordinary/", ordinary_view),
]
