# services/models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ServiceCategory(models.Model):
    SERVICE_TYPES = (
        ('gas', 'Gas Services'),
        ('roadside_mechanical', 'Roadside Mechanical'),
        ('roadside_fuel', 'Roadside Fuel Refill'),
        ('roadside_towing', 'Roadside Towing'),
        ('oxygen', 'Oxygen Refill'),
        ('mechanic', 'Mechanic Services'),
    )
    
    name = models.CharField(max_length=100, choices=SERVICE_TYPES)
    description = models.TextField()
    icon = models.CharField(max_length=50, blank=True)  # For UI icons
    
    def __str__(self):
        return self.get_name_display()

class Service(models.Model):
    vendor = models.ForeignKey('vendors.Vendor', on_delete=models.CASCADE, related_name='services')
    category = models.ForeignKey(ServiceCategory, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.vendor.business_name}"

class ServiceImage(models.Model):
    service = models.ForeignKey(Service, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='service_images/')
    is_primary = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Image for {self.service.name}"