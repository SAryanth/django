from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from rest_framework import filters
from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter

from .models import Product
from .serializers import ProductSerializer


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


@extend_schema_view(
    list=extend_schema(tags=['Products'], description='List products'),
    retrieve=extend_schema(tags=['Products'], description='Retrieve a product'),
    create=extend_schema(tags=['Products'], description='Create a product'),
    update=extend_schema(tags=['Products'], description='Update a product'),
    partial_update=extend_schema(tags=['Products'], description='Partially update a product'),
    destroy=extend_schema(tags=['Products'], description='Delete a product'),
)
class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['in_stock']
    search_fields = ['name', 'description']
    ordering_fields = ['price', 'created_at']
