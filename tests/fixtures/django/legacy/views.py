from django.contrib.auth.decorators import login_required, permission_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated


@login_required
def dashboard(request):
    return render(request, "dashboard.html")


@permission_required("reports.view_report")
def reports(request):
    return render(request, "reports.html")


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def widgets(request):
    return Response([])


def public_status(request):
    return JsonResponse({"ok": True})
