from .models import Account


def create_account(email: str):
    return Account.objects.create(email=email)
