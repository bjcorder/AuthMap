from django.db import models


class Account(models.Model):
    email = models.EmailField()
    disabled = models.BooleanField(default=False)


def create_account(email: str):
    return Account.objects.create(email=email)


def disable_account(account_id: int):
    return Account.objects.filter(id=account_id).update(disabled=True)


def delete_account(account_id: int):
    return Account.objects.filter(id=account_id).delete()
