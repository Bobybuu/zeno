# orders/serializers.py
from rest_framework import serializers
from .models import Order, OrderTracking, Cart, CartItem, OrderItem

class OrderTrackingSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderTracking
        fields = ['id', 'status', 'note', 'created_at']

class CartItemSerializer(serializers.ModelSerializer):
    service_details = serializers.SerializerMethodField()
    gas_product_details = serializers.SerializerMethodField()
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    item_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CartItem
        fields = [
            'id', 'item_type', 'service', 'service_details', 'gas_product', 
            'gas_product_details', 'quantity', 'total_price', 'item_name', 'added_at'
        ]
        read_only_fields = ['total_price', 'item_name']
    
    def get_service_details(self, obj):
        if obj.service:
            from services.serializers import ServiceSerializer
            return ServiceSerializer(obj.service).data
        return None
    
    def get_gas_product_details(self, obj):
        if obj.gas_product:
            from vendors.serializers import GasProductListSerializer
            return GasProductListSerializer(obj.gas_product).data
        return None
    
    def get_item_name(self, obj):
        return obj.item_name

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    item_count = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = Cart
        fields = ['id', 'items', 'total_amount', 'item_count', 'created_at', 'updated_at']

class OrderItemSerializer(serializers.ModelSerializer):
    service_details = serializers.SerializerMethodField()
    gas_product_details = serializers.SerializerMethodField()
    item_name = serializers.SerializerMethodField()
    
    class Meta:
        model = OrderItem
        fields = [
            'id', 'item_type', 'service', 'service_details', 'gas_product', 
            'gas_product_details', 'quantity', 'unit_price', 'total_price', 'item_name'
        ]
    
    def get_service_details(self, obj):
        if obj.service:
            from services.serializers import ServiceSerializer
            return ServiceSerializer(obj.service).data
        return None
    
    def get_gas_product_details(self, obj):
        if obj.gas_product:
            from vendors.serializers import GasProductListSerializer
            return GasProductListSerializer(obj.gas_product).data
        return None
    
    def get_item_name(self, obj):
        if obj.item_type == 'service' and obj.service:
            return obj.service.name
        elif obj.item_type == 'gas_product' and obj.gas_product:
            return f"{obj.gas_product.name} ({obj.gas_product.gas_type})"
        return "Unknown Item"

class OrderSerializer(serializers.ModelSerializer):
    service_details = serializers.SerializerMethodField()
    gas_product_details = serializers.SerializerMethodField()
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    customer_name = serializers.CharField(source='customer.get_full_name', read_only=True)
    tracking = OrderTrackingSerializer(many=True, read_only=True)
    order_items = OrderItemSerializer(many=True, read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'customer', 'customer_name', 'vendor', 'vendor_name', 
            'order_type', 'service', 'service_details', 'gas_product', 'gas_product_details',
            'quantity', 'unit_price', 'total_amount', 'delivery_type',
            'location_lat', 'location_lng', 'delivery_address', 'special_instructions', 
            'status', 'payment_status', 'created_at', 'updated_at', 
            'confirmed_at', 'completed_at', 'tracking', 'order_items'
        ]
        read_only_fields = [
            'customer', 'vendor', 'unit_price', 'total_amount', 
            'created_at', 'updated_at', 'service_details', 'gas_product_details'
        ]
    
    def get_service_details(self, obj):
        if obj.service:
            from services.serializers import ServiceSerializer
            return ServiceSerializer(obj.service).data
        return None
    
    def get_gas_product_details(self, obj):
        if obj.gas_product:
            from vendors.serializers import GasProductListSerializer
            return GasProductListSerializer(obj.gas_product).data
        return None

class CreateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = [
            'service', 'quantity', 'location_lat', 'location_lng', 
            'delivery_address', 'special_instructions'
        ]
    
    def validate(self, data):
        service = data['service']
        if not service.available:
            raise serializers.ValidationError("This service is currently unavailable")
        return data

class CreateGasProductOrderSerializer(serializers.ModelSerializer):
    gas_product_id = serializers.IntegerField(write_only=True)
    delivery_type = serializers.ChoiceField(choices=[
        ('delivery', 'Delivery'), 
        ('pickup', 'Pickup')
    ], default='delivery')
    
    class Meta:
        model = Order
        fields = [
            'gas_product_id', 'quantity', 'delivery_type', 'location_lat', 
            'location_lng', 'delivery_address', 'special_instructions'
        ]
    
    def validate(self, data):
        gas_product_id = data.get('gas_product_id')
        quantity = data.get('quantity', 1)
        
        try:
            from vendors.models import GasProduct
            gas_product = GasProduct.objects.get(id=gas_product_id, is_active=True, is_available=True)
        except GasProduct.DoesNotExist:
            raise serializers.ValidationError("Gas product not found or unavailable")
        
        # Check stock availability
        if gas_product.stock_quantity < quantity:
            raise serializers.ValidationError(
                f"Only {gas_product.stock_quantity} units available in stock"
            )
        
        data['gas_product'] = gas_product
        data['vendor'] = gas_product.vendor
        data['unit_price'] = gas_product.price_with_cylinder
        
        return data

class CreateMixedOrderSerializer(serializers.Serializer):
    """Serializer for orders containing both services and gas products"""
    items = serializers.ListField(
        child=serializers.DictField(),
        min_length=1
    )
    delivery_type = serializers.ChoiceField(choices=[
        ('delivery', 'Delivery'), 
        ('pickup', 'Pickup'),
        ('on_site', 'On-Site Service')
    ], required=True)
    delivery_address = serializers.CharField(required=True)
    special_instructions = serializers.CharField(required=False, allow_blank=True)
    
    def validate_items(self, items):
        if len(items) == 0:
            raise serializers.ValidationError("At least one item is required")
        
        validated_items = []
        for item in items:
            item_type = item.get('type')
            item_id = item.get('id')
            quantity = item.get('quantity', 1)
            
            if item_type == 'service':
                from services.models import Service
                try:
                    service = Service.objects.get(id=item_id, available=True)
                    validated_items.append({
                        'type': 'service',
                        'object': service,
                        'quantity': quantity,
                        'unit_price': service.price,
                        'vendor': service.vendor
                    })
                except Service.DoesNotExist:
                    raise serializers.ValidationError(f"Service with ID {item_id} not found")
                    
            elif item_type == 'gas_product':
                from vendors.models import GasProduct
                try:
                    gas_product = GasProduct.objects.get(id=item_id, is_active=True, is_available=True)
                    if gas_product.stock_quantity < quantity:
                        raise serializers.ValidationError(
                            f"Not enough stock for {gas_product.name}"
                        )
                    validated_items.append({
                        'type': 'gas_product',
                        'object': gas_product,
                        'quantity': quantity,
                        'unit_price': gas_product.price_with_cylinder,
                        'vendor': gas_product.vendor
                    })
                except GasProduct.DoesNotExist:
                    raise serializers.ValidationError(f"Gas product with ID {item_id} not found")
            else:
                raise serializers.ValidationError(f"Invalid item type: {item_type}")
        
        # Check if all items belong to the same vendor
        vendors = set(item['vendor'].id for item in validated_items)
        if len(vendors) > 1:
            raise serializers.ValidationError("All items must be from the same vendor")
        
        return validated_items

class UpdateOrderStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['status']
    
    def validate_status(self, value):
        valid_transitions = {
            'pending': ['confirmed', 'cancelled'],
            'confirmed': ['in_progress', 'cancelled'],
            'in_progress': ['completed', 'cancelled'],
            'completed': [],
            'cancelled': [],
            'failed': [],
        }
        
        current_status = self.instance.status
        if value not in valid_transitions.get(current_status, []):
            raise serializers.ValidationError(
                f"Cannot change status from {current_status} to {value}"
            )
        return value