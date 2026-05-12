from django.db import models


class Account(models.Model):
    email = models.EmailField()
    disabled = models.BooleanField(default=False)


def create_account(email: str):
    return Account.objects.create(email=email)


def disable_account(account_id: int):
    return Account.objects.filter(id=account_id).update(disabled=True)


def bulk_disable(accounts: list[Account]):
    return Account.objects.bulk_update(accounts, ["disabled"])


def save_account(account_id: int):
    account = Account.objects.get(id=account_id)
    account.disabled = True
    account.save()
    return account


def delete_account(account_id: int):
    return Account.objects.filter(id=account_id).delete()


def delete_instance(account_id: int):
    account = Account.objects.get(id=account_id)
    account.delete()

