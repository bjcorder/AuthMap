from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet, ViewSet

from .models import Account
from .services import create_account


def require_permission(user):
    return True


def status(request):
    return {"ok": True}


def legacy_detail(request, slug):
    return {"slug": slug}


def index(request):
    return create_account("index@example.test")


def dynamic_view(request):
    return {"dynamic": True}


class AccountDetailView:
    def get(self, request, pk):
        account = Account.objects.get(pk=pk)
        if request.user.role != "admin":
            return {"denied": True}
        account.disabled = False
        account.save()
        return account

    def delete(self, request, pk):
        return Account.objects.filter(pk=pk).delete()


class UserViewSet(ModelViewSet):
    lookup_field = "uuid"

    def list(self, request):
        require_permission(request.user)
        return []

    def create(self, request):
        return Account.objects.create(email=request.data["email"])

    @action(detail=True, methods=["post"], url_path="disable")
    def disable(self, request, uuid=None):
        return Account.objects.filter(uuid=uuid).update(disabled=True)


class DynamicViewSet(ViewSet):
    def list(self, request):
        return []
