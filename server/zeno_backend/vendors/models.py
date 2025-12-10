# vendors/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

User = get_user_model()

class Vendor(models.Model):
    VENDOR_TYPES = (
        ('gas_station', 'Gas Station'),
        ('mechanic', 'Mechanic'),
        ('hospital', 'Hospital'),
        ('roadside_assistance', 'Roadside Assistance'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor_profile_simple')
    business_name = models.CharField(max_length=255)
    business_type = models.CharField(max_length=50, choices=VENDOR_TYPES)
    description = models.TextField(blank=True)
    
    # Location details
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    address = models.TextField()
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100, default='Kenya')
    
    # Contact information
    contact_number = models.CharField(max_length=15)
    email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    
    # Business details
    opening_hours = models.CharField(max_length=100, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    # Ratings
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_reviews = models.IntegerField(default=0)
    
    # Gas-specific fields
    delivery_radius_km = models.IntegerField(default=5, help_text="Delivery radius in kilometers")
    min_order_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    delivery_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.business_name} ({self.get_business_type_display()})"
    
    @property
    def total_gas_products(self):
        return self.gas_products.filter(is_active=True).count()
    
    @property
    def available_gas_products(self):
        return self.gas_products.filter(is_active=True, stock_quantity__gt=0)
    
    class Meta:
        ordering = ['-created_at']


class GasProduct(models.Model):
    GAS_TYPES = (
        ('lpg', 'LPG (Cooking Gas)'),
        ('cng', 'CNG (Compressed Natural Gas)'),
        ('oxygen', 'Medical Oxygen'),
        ('nitrogen', 'Industrial Nitrogen'),
        ('acetylene', 'Acetylene'),
    )
    
    CYLINDER_SIZES = (
        ('1kg', '1 kg'),
        ('3kg', '3 kg'),
        ('5kg', '5 kg'),
        ('6kg', '6 kg'),
        ('13kg', '13 kg'),
        ('15kg', '15 kg'),
        ('22kg', '22 kg'),
        ('50kg', '50 kg'),
        ('100kg', '100 kg'),
    )
    
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='gas_products')
    
    # Product Identification
    name = models.CharField(max_length=200, help_text="e.g., Pro Gas LPG, K-Gas, etc.")
    gas_type = models.CharField(max_length=20, choices=GAS_TYPES, default='lpg')
    cylinder_size = models.CharField(max_length=10, choices=CYLINDER_SIZES, default='13kg')
    brand = models.CharField(max_length=100, blank=True)
    
    # Pricing
    price_with_cylinder = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text="Price including cylinder deposit"
    )
    price_without_cylinder = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text="Price for gas refill only (customer provides cylinder)"
    )
    cylinder_deposit = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        default=0.00,
        help_text="Cylinder deposit amount"
    )
    
    # Inventory Management
    stock_quantity = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Current available stock"
    )
    min_stock_alert = models.IntegerField(
        default=5,
        validators=[MinValueValidator(0)],
        help_text="Alert when stock reaches this level"
    )
    
    # Product Details
    description = models.TextField(blank=True, help_text="Product features and specifications")
    ingredients = models.TextField(blank=True, help_text="Gas composition and purity")
    safety_instructions = models.TextField(blank=True)
    
    # Status & Visibility
    is_available = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    featured = models.BooleanField(default=False)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.get_cylinder_size_display()} ({self.vendor.business_name})"
    
    @property
    def in_stock(self):
        return self.stock_quantity > 0
    
    @property
    def low_stock(self):
        return 0 < self.stock_quantity <= self.min_stock_alert
    
    def save(self, *args, **kwargs):
        # Auto-calculate cylinder deposit if not set
        if not self.cylinder_deposit and self.price_with_cylinder and self.price_without_cylinder:
            self.cylinder_deposit = self.price_with_cylinder - self.price_without_cylinder
        
        # Update availability based on stock
        self.is_available = self.in_stock and self.is_active
        
        super().save(*args, **kwargs)
    
    class Meta:
        ordering = ['gas_type', 'cylinder_size', 'name']
        unique_together = ['vendor', 'gas_type', 'cylinder_size', 'brand']


class GasProductImage(models.Model):
    product = models.ForeignKey(GasProduct, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='gas_products/')
    alt_text = models.CharField(max_length=200, blank=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Image for {self.product.name}"


class GasPriceHistory(models.Model):
    product = models.ForeignKey(GasProduct, on_delete=models.CASCADE, related_name='price_history')
    price_with_cylinder = models.DecimalField(max_digits=10, decimal_places=2)
    price_without_cylinder = models.DecimalField(max_digits=10, decimal_places=2)
    effective_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Price history for {self.product.name} on {self.effective_date.date()}"


class VendorReview(models.Model):
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='reviews')
    customer = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Review for {self.vendor.business_name} by {self.customer.username}"


class OperatingHours(models.Model):
    DAYS_OF_WEEK = (
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday'),
    )
    
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='operating_hours')
    day = models.IntegerField(choices=DAYS_OF_WEEK)
    opening_time = models.TimeField()
    closing_time = models.TimeField()
    is_closed = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.get_day_display()}: {self.opening_time} - {self.closing_time}"