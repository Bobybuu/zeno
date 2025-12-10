# orders/views.py
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone

# Import Service model from services app
from services.models import Service
from vendors.models import Vendor, GasProduct  # Add this import too

from .models import Order, OrderTracking, Cart, CartItem, OrderItem
from .serializers import (
    OrderSerializer, CreateOrderSerializer, CreateGasProductOrderSerializer,
    CreateMixedOrderSerializer, UpdateOrderStatusSerializer,
    CartSerializer, CartItemSerializer, OrderTrackingSerializer
)

class IsVendorOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.vendor.user == request.user

class IsOrderOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.customer == request.user

class CartViewSet(viewsets.ModelViewSet):
    serializer_class = CartSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    # Add queryset attribute
    queryset = Cart.objects.all()
    
    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def my_cart(self, request):
        """Get the current user's cart"""
        cart, created = Cart.objects.get_or_create(user=request.user)
        serializer = self.get_serializer(cart)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def add_item(self, request):
        """Add service to cart"""
        cart, created = Cart.objects.get_or_create(user=request.user)
        service_id = request.data.get('service_id')
        quantity = request.data.get('quantity', 1)
        
        try:
            service = Service.objects.get(id=service_id, available=True)
        except Service.DoesNotExist:
            return Response(
                {'error': 'Service not found or unavailable'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart, service=service,
            defaults={'quantity': quantity}
        )
        
        if not created:
            cart_item.quantity += quantity
            cart_item.save()
        
        serializer = CartItemSerializer(cart_item)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def add_gas_product(self, request):
        """Add gas product to cart"""
        cart, created = Cart.objects.get_or_create(user=request.user)
        product_id = request.data.get('product_id')
        quantity = request.data.get('quantity', 1)
        
        try:
            gas_product = GasProduct.objects.get(
                id=product_id, 
                is_active=True, 
                is_available=True
            )
        except GasProduct.DoesNotExist:
            return Response(
                {'error': 'Gas product not found or unavailable'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check stock
        if gas_product.stock_quantity < quantity:
            return Response(
                {'error': f'Only {gas_product.stock_quantity} units available'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart, 
            gas_product=gas_product,
            defaults={'quantity': quantity}
        )
        
        if not created:
            cart_item.quantity += quantity
            cart_item.save()
        
        serializer = CartItemSerializer(cart_item)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def update_quantity(self, request):
        """Update item quantity in cart"""
        cart = get_object_or_404(Cart, user=request.user)
        item_id = request.data.get('item_id')
        quantity = request.data.get('quantity', 1)
        
        try:
            cart_item = CartItem.objects.get(id=item_id, cart=cart)
            if quantity <= 0:
                cart_item.delete()
                return Response({'message': 'Item removed from cart'})
            else:
                cart_item.quantity = quantity
                cart_item.save()
                serializer = CartItemSerializer(cart_item)
                return Response(serializer.data)
        except CartItem.DoesNotExist:
            return Response(
                {'error': 'Cart item not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def remove_item(self, request):
        """Remove item from cart"""
        cart = get_object_or_404(Cart, user=request.user)
        item_id = request.data.get('item_id')
        
        try:
            cart_item = CartItem.objects.get(id=item_id, cart=cart)
            cart_item.delete()
            return Response({'message': 'Item removed from cart'})
        except CartItem.DoesNotExist:
            return Response(
                {'error': 'Cart item not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def clear(self, request):
        """Clear entire cart"""
        cart = get_object_or_404(Cart, user=request.user)
        cart.items.all().delete()
        return Response({'message': 'Cart cleared successfully'})

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    # Add queryset attribute
    queryset = Order.objects.all()
    
    def get_queryset(self):
        user = self.request.user
        if user.user_type in ['vendor', 'mechanic'] and hasattr(user, 'vendor_profile'):
            return Order.objects.filter(vendor=user.vendor_profile)
        return Order.objects.filter(customer=user)
    
    def get_serializer_class(self):
        if self.action == 'create':
            # Determine which serializer to use based on request data
            if 'gas_product_id' in self.request.data:
                return CreateGasProductOrderSerializer
            elif 'items' in self.request.data:
                return CreateMixedOrderSerializer
            else:
                return CreateOrderSerializer
        elif self.action in ['update', 'partial_update']:
            return UpdateOrderStatusSerializer
        return OrderSerializer
    
    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'update_status']:
            return [permissions.IsAuthenticated(), IsVendorOwner()]
        elif self.action in ['destroy']:
            return [permissions.IsAuthenticated(), IsOrderOwner()]
        return [permissions.IsAuthenticated()]
    
    @transaction.atomic
    def create(self, request):
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        if isinstance(serializer, CreateGasProductOrderSerializer):
            return self._create_gas_product_order(serializer.validated_data)
        elif isinstance(serializer, CreateMixedOrderSerializer):
            return self._create_mixed_order(serializer.validated_data)
        else:
            return self._create_service_order(serializer.validated_data)
    
    def _create_gas_product_order(self, validated_data):
        """Create order for gas product"""
        gas_product = validated_data['gas_product']
        quantity = validated_data['quantity']
        
        # Update product stock
        gas_product.stock_quantity -= quantity
        gas_product.save()
        
        # Create order
        order = Order.objects.create(
            customer=self.request.user,
            vendor=validated_data['vendor'],
            order_type='gas_product',
            gas_product=gas_product,
            quantity=quantity,
            unit_price=validated_data['unit_price'],
            delivery_type=validated_data['delivery_type'],
            location_lat=validated_data.get('location_lat'),
            location_lng=validated_data.get('location_lng'),
            delivery_address=validated_data.get('delivery_address', ''),
            special_instructions=validated_data.get('special_instructions', '')
        )
        
        # Create initial tracking
        OrderTracking.objects.create(order=order, status='pending')
        
        return Response(OrderSerializer(order).data, status=status.HTTP_201_CREATED)
    
    def _create_mixed_order(self, validated_data):
        """Create order with multiple items"""
        items = validated_data['items']
        vendor = items[0]['vendor']  # All items have same vendor (validated)
        
        # Create main order
        order = Order.objects.create(
            customer=self.request.user,
            vendor=vendor,
            order_type='mixed',
            delivery_type=validated_data['delivery_type'],
            delivery_address=validated_data['delivery_address'],
            special_instructions=validated_data.get('special_instructions', ''),
            unit_price=0,  # Will be calculated from items
            total_amount=0  # Will be calculated from items
        )
        
        total_amount = 0
        
        # Create order items
        for item_data in items:
            order_item = OrderItem.objects.create(
                order=order,
                item_type=item_data['type'],
                service=item_data['object'] if item_data['type'] == 'service' else None,
                gas_product=item_data['object'] if item_data['type'] == 'gas_product' else None,
                quantity=item_data['quantity'],
                unit_price=item_data['unit_price']
            )
            
            total_amount += order_item.total_price
            
            # Update stock for gas products
            if item_data['type'] == 'gas_product':
                gas_product = item_data['object']
                gas_product.stock_quantity -= item_data['quantity']
                gas_product.save()
        
        # Update order total
        order.total_amount = total_amount
        order.unit_price = total_amount  # For mixed orders, unit_price represents order total
        order.save()
        
        # Create initial tracking
        OrderTracking.objects.create(order=order, status='pending')
        
        return Response(OrderSerializer(order).data, status=status.HTTP_201_CREATED)
    
    def _create_service_order(self, validated_data):
        """Original service order creation"""
        service = validated_data['service']
        vendor = service.vendor
        
        order = Order.objects.create(
            customer=self.request.user,
            vendor=vendor,
            order_type='service',
            service=service,
            quantity=validated_data['quantity'],
            unit_price=service.price,
            location_lat=validated_data.get('location_lat'),
            location_lng=validated_data.get('location_lng'),
            delivery_address=validated_data['delivery_address'],
            special_instructions=validated_data.get('special_instructions', '')
        )
        
        OrderTracking.objects.create(order=order, status='pending')
        
        return Response(OrderSerializer(order).data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update order status"""
        order = self.get_object()
        serializer = UpdateOrderStatusSerializer(order, data=request.data)
        serializer.is_valid(raise_exception=True)
        
        new_status = serializer.validated_data['status']
        order.status = new_status
        
        # Update timestamps based on status
        if new_status == 'confirmed' and not order.confirmed_at:
            order.confirmed_at = timezone.now()
        elif new_status == 'completed' and not order.completed_at:
            order.completed_at = timezone.now()
        
        order.save()
        
        # Add tracking entry
        OrderTracking.objects.create(
            order=order, 
            status=new_status,
            note=request.data.get('note', '')
        )
        
        return Response(OrderSerializer(order).data)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel order and restore stock if applicable"""
        order = self.get_object()
        
        if order.status in ['completed', 'cancelled']:
            return Response(
                {'error': f'Cannot cancel order with status: {order.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Restore stock for gas product orders
        if order.gas_product and order.order_type == 'gas_product':
            order.gas_product.stock_quantity += order.quantity
            order.gas_product.save()
        
        elif order.order_type == 'mixed':
            # Restore stock for all gas product items
            for item in order.items.filter(item_type='gas_product'):
                if item.gas_product:
                    item.gas_product.stock_quantity += item.quantity
                    item.gas_product.save()
        
        order.status = 'cancelled'
        order.save()
        
        OrderTracking.objects.create(
            order=order, 
            status='cancelled',
            note=request.data.get('note', 'Order cancelled by user')
        )
        
        return Response(OrderSerializer(order).data)
    
    @action(detail=False, methods=['get'])
    def vendor_orders(self, request):
        """Get orders for vendor's services"""
        if not hasattr(request.user, 'vendor_profile'):
            return Response(
                {'error': 'User is not a vendor'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        vendor = request.user.vendor_profile
        orders = Order.objects.filter(vendor=vendor)
        
        status_filter = request.query_params.get('status')
        if status_filter:
            orders = orders.filter(status=status_filter)
        
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def gas_product_orders(self, request):
        """Get gas product orders for vendor"""
        if not hasattr(request.user, 'vendor_profile'):
            return Response(
                {'error': 'User is not a vendor'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        vendor = request.user.vendor_profile
        orders = Order.objects.filter(
            vendor=vendor,
            order_type__in=['gas_product', 'mixed']
        )
        
        status_filter = request.query_params.get('status')
        if status_filter:
            orders = orders.filter(status=status_filter)
        
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def tracking(self, request, pk=None):
        """Get order tracking history"""
        order = self.get_object()
        tracking = order.tracking.all()
        serializer = OrderTrackingSerializer(tracking, many=True)
        return Response(serializer.data)