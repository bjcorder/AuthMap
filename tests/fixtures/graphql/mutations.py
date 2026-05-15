import graphene

from shop.permissions import ProductPermissions


class ProductCreate(BaseMutation):
    class Meta:
        permissions = (ProductPermissions.MANAGE_PRODUCTS,)

    @classmethod
    def perform_mutation(cls, root, info, **data):
        return Product.objects.create(**data)


class PublicCatalogQuery(graphene.ObjectType):
    products = graphene.List(Product)


class GeneratedSchemaField:
    permissions = sgqlc.types.Field(String)


class Mutation(sgqlc.types.Type):
    permissions = sgqlc.types.Field(String)
