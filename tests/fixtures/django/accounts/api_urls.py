from rest_framework.routers import SimpleRouter

from . import views

router = SimpleRouter()
router.register("exported", views.ProjectReadOnlyViewSet, basename="exported")

urlpatterns = router.urls
