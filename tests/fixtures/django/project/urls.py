from django.urls import include, path, re_path

from accounts import urls as account_urls
from accounts import views

urlpatterns = [
    path("status/", views.status, name="status"),
    re_path(r"^legacy/(?P<slug>[-\w]+)/$", views.legacy_detail, name="legacy_detail"),
    path("accounts/", include(account_urls)),
    path("dynamic/", include(get_urlconf())),
]
