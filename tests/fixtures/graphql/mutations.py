import graphene

from shop.permissions import ProductPermissions


class BaseMutation(graphene.Mutation):
    class Meta:
        abstract = True


class ModelDeleteMutation(BaseMutation):
    class Meta:
        abstract = True


class ProductCreate(BaseMutation):
    class Meta:
        permissions = (ProductPermissions.MANAGE_PRODUCTS,)

    @classmethod
    def perform_mutation(cls, root, info, **data):
        return Product.objects.create(**data)


class CreateToken(BaseMutation):
    class Meta:
        permissions = ()


class RequestPasswordReset(BaseMutation):
    class Meta:
        permissions = []


class CheckoutCreate(BaseMutation):
    @classmethod
    def perform_mutation(cls, root, info, **data):
        return Checkout.objects.create(**data)


class AccountQueries(graphene.ObjectType):
    products = graphene.List(Product)
    customers = PermissionsField(
        UserCountableConnection,
        permissions=[ProductPermissions.MANAGE_PRODUCTS],
    )


class AccountMutations(graphene.ObjectType):
    token_create = CreateToken.Field()
    request_password_reset = RequestPasswordReset.Field()
    checkout_create = CheckoutCreate.Field()
    product_create = ProductCreate.Field()


class ChoiceValue(graphene.ObjectType):
    value = graphene.String()


class GeneratedSchemaField:
    permissions = sgqlc.types.Field(String)


class Mutation(sgqlc.types.Type):
    permissions = sgqlc.types.Field(String)
