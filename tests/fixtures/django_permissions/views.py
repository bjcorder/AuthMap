from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin as LR
from django.utils.decorators import method_decorator
from django.views import View
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet


class PermissionsViewSet(ModelViewSet):
    permission_classes = [IsAdminUser]

    def list(self, request):
        return []

    @action(detail=False, methods=["post"], permission_classes=[], authentication_classes=[])
    def public(self, request):
        return []

    @action(detail=False, methods=["post"], authentication_classes=[SessionAuthentication])
    def auth_only(self, request):
        return []

    @action(detail=False, methods=["post"], permission_classes=[IsAdminUser] if FLAG else [])
    def dynamic(self, request):
        return []


class SettingsView(APIView):
    def get(self, request):
        return []


@api_view(["GET"])
@permission_classes([
    # Explicitly public.
])
@authentication_classes([])
def public_api(request):
    return []


@method_decorator(login_required, name="get")
class ConcreteWrapped(View):
    def get(self, request):
        return []

    def post(self, request):
        return []


class DispatchWrapped(View):
    @method_decorator(permission_required("reports.view_report"))
    def dispatch(self, request):
        return []

    def get(self, request):
        return []


class FirstMixin(LR):
    pass


class SecondMixin(FirstMixin):
    pass


class AliasedView(SecondMixin, View):
    def get(self, request):
        return []


def ordinary_view(request):
    return []
