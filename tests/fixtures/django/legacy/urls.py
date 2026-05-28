from django.conf.urls import url
from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("reports/", views.reports, name="reports"),
    url(r"^widgets/$", views.widgets, name="widgets"),
]

urlpatterns += [
    path("status/", views.public_status, name="public_status"),
]
