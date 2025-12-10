# orders/models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Cart(models.Model):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='cart'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def total_amount(self):
        return sum(item.total_price for item in self.items.all())

    @property
    def item_count(self):
        return self.items.count()

    def __str__(self):
        return f"Cart for {self.user.username}"

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    item_type = models.CharField(max_length=20, choices=[
        ('service', 'Service'),
        ('gas_product', 'Gas Product')
    ], default='service')
    service = models.ForeignKey('services.Service', on_delete=models.CASCADE, 
                               null=True, blank=True)
    gas_product = models.ForeignKey('vendors.GasProduct', on_delete=models.CASCADE,
                                   null=True, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    
    @property
    def unit_price(self):
        if self.service:
            return self.service.price
        elif self.gas_product:
            return self.gas_product.price_with_cylinder
        return 0
    
    @property
    def total_price(self):
        return self.unit_price * self.quantity
    
    @property
    def item_name(self):
        if self.service:
            return self.service.name
        elif self.gas_product:
            return self.gas_product.name
        return "Unknown Item"
    
    class Meta:
        unique_together = ['cart', 'service', 'gas_product']

class Order(models.Model):
    ORDER_TYPES = [
        ('service', 'Service'),
        ('gas_product', 'Gas Product'),
        ('mixed', 'Mixed Order'),
    ]
    
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    vendor = models.ForeignKey('vendors.Vendor', on_delete=models.CASCADE, related_name='orders')
    order_type = models.CharField(max_length=20, choices=ORDER_TYPES, default='service')
    
    # Service-specific fields
    service = models.ForeignKey('services.Service', on_delete=models.SET_NULL, 
                               null=True, blank=True, related_name='orders')
    
    # Gas product-specific fields
    gas_product = models.ForeignKey('vendors.GasProduct', on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name='orders')
    
    # Common fields
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Delivery information
    delivery_type = models.CharField(max_length=20, choices=[
        ('delivery', 'Delivery'),
        ('pickup', 'Pickup'),
        ('on_site', 'On-Site Service')
    ], default='delivery')
    
    location_lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    delivery_address = models.TextField()
    special_instructions = models.TextField(blank=True)
    
    # Status fields
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('failed', 'Failed')
    ], default='pending')
    
    payment_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded')
    ], default='pending')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.total_amount and self.unit_price:
            self.total_amount = self.unit_price * self.quantity
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Order #{self.id} - {self.customer.username}"

class OrderItem(models.Model):
    """For mixed orders containing both services and products"""
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    item_type = models.CharField(max_length=20, choices=[
        ('service', 'Service'),
        ('gas_product', 'Gas Product')
    ])
    service = models.ForeignKey('services.Service', on_delete=models.CASCADE, 
                               null=True, blank=True)
    gas_product = models.ForeignKey('vendors.GasProduct', on_delete=models.CASCADE,
                                   null=True, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    
    def save(self, *args, **kwargs):
        if self.unit_price and self.quantity:
            self.total_price = self.unit_price * self.quantity
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.item_type} - Order #{self.order.id}"

class OrderTracking(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='tracking')
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('failed', 'Failed')
    ])
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Tracking - Order #{self.order.id} - {self.status}"
    
    class Meta:
        ordering = ['-created_at']