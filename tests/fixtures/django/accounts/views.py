from rest_framework.decorators import action
from rest_framework import mixins as drf_mixins
from rest_framework.viewsets import GenericViewSet, ModelViewSet, ReadOnlyModelViewSet, ViewSet
from shared import generic

from .models import Account
from .services import create_account


def get_url_path():
    return "dynamic"


def require_permission(user):
    return True


def register_model_view(model, name="", path=None, detail=True):
    def wrapper(cls):
        return cls

    return wrapper


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


@register_model_view(Account, "list", path="", detail=False)
class GeneratedAccountListView(ProjectModelViewSet):
    pass


@register_model_view(Account, "edit", path="edit")
class GeneratedAccountEditView(generic.ObjectEditView):
    pass


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


class ReadOnlyAccountViewSet(ReadOnlyModelViewSet):
    def nested_helpers(self):
        def destroy():
            return Account.objects.filter(active=False).delete()

        return destroy


class ReadOnlyAuditViewSet(ReadOnlyModelViewSet):
    @action(detail=False, methods=["post"], url_path="refresh")
    def refresh(self, request):
        return Account.objects.filter(active=True).update(reviewed=True)


class MyModelViewSet(ViewSet):
    pass


class CustomModelBackedViewSet(MyModelViewSet):
    def list(self, request):
        return []

    @action(detail=False, methods=["post"], url_path=get_url_path())
    def recalculate(self, request):
        return []


class DynamicViewSet(ViewSet):
    def list(self, request):
        return []


class ProjectModelViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            self.queryset = self.queryset.restrict(request.user, "view")
        return super().initial(request, *args, **kwargs)


class ProjectReadOnlyViewSet(ReadOnlyModelViewSet):
    permission_classes = [DjangoObjectPermissions]


class ProjectMixinViewSet(
    drf_mixins.ListModelMixin,
    drf_mixins.CreateModelMixin,
    GenericViewSet,
):
    pass


class InheritedProjectViewSet(ProjectModelViewSet):
    pass


class InheritedReadOnlyProjectViewSet(ProjectReadOnlyViewSet):
    pass


class MixinBackedProjectViewSet(ProjectMixinViewSet):
    pass
