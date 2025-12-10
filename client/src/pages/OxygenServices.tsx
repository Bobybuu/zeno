import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, MapPin, Phone, Star, Heart, Loader2, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useToast } from "@/components/ui/use-toast";
import BottomNav from "@/components/BottomNav";
import { motion } from "framer-motion";

interface OxygenProvider {
  id: number;
  business_name: string;
  business_type: string;
  description: string;
  address: string;
  city: string;
  country: string;
  contact_number: string;
  email: string;
  latitude: string;
  longitude: string;
  average_rating: string;
  total_reviews: number;
  is_verified: boolean;
  is_active: boolean;
  services: Array<{
    id: number;
    name: string;
    description: string;
    price: string;
    available: boolean;
    category: string;
  }>;
  operating_hours: Array<{
    id: number;
    day: number;
    opening_time: string;
    closing_time: string;
    is_closed: boolean;
  }>;
}

const OxygenServices = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [providers, setProviders] = useState<OxygenProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);

  useEffect(() => {
    getUserLocation();
    fetchOxygenProviders();
  }, []);

  const getUserLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setUserLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude
          });
        },
        (error) => {
          console.error('Error getting location:', error);
          toast({
            title: "Location Access",
            description: "Enable location for better service recommendations",
            variant: "destructive"
          });
        }
      );
    }
  };

  const fetchOxygenProviders = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const params = new URLSearchParams({
        business_type: 'hospital',
        ...(userLocation && {
          lat: userLocation.lat.toString(),
          lng: userLocation.lng.toString(),
          radius: '50' // 50km radius for hospitals
        })
      });

      const response = await fetch(`/api/vendors/?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const providersData = await response.json();
        setProviders(providersData);
      } else {
        throw new Error('Failed to fetch oxygen providers');
      }
    } catch (error) {
      console.error('Error fetching oxygen providers:', error);
      toast({
        title: "Error",
        description: "Failed to load oxygen refill services",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateDistance = (lat1: number, lng1: number, lat2: number, lng2: number): string => {
    if (!userLocation) return "Unknown";
    
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
      Math.sin(dLng/2) * Math.sin(dLng/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const distance = R * c;
    
    return distance < 1 ? `${Math.round(distance * 1000)}m` : `${distance.toFixed(1)}km`;
  };

  const getOxygenServicePrice = (provider: OxygenProvider): string => {
    const oxygenService = provider.services.find(service => 
      service.name.toLowerCase().includes('oxygen') || 
      service.category.toLowerCase().includes('oxygen')
    );
    
    if (oxygenService) {
      return `KSh ${parseFloat(oxygenService.price).toLocaleString()}`;
    }
    
    // Fallback to minimum service price
    if (provider.services.length > 0) {
      const minPrice = Math.min(...provider.services.map(s => parseFloat(s.price)));
      return `From KSh ${minPrice.toLocaleString()}`;
    }
    
    return "Contact for pricing";
  };

  const getCurrentOperatingStatus = (provider: OxygenProvider): { status: string; color: string } => {
    const now = new Date();
    const currentDay = now.getDay(); // 0 = Sunday, 6 = Saturday
    const currentTime = now.toTimeString().slice(0, 8); // HH:MM:SS
    
    const todayHours = provider.operating_hours.find(hours => hours.day === currentDay);
    
    if (!todayHours || todayHours.is_closed) {
      return { status: "Closed", color: "text-destructive" };
    }
    
    if (currentTime >= todayHours.opening_time && currentTime <= todayHours.closing_time) {
      return { status: "Open Now", color: "text-green-600" };
    }
    
    return { status: "Closed", color: "text-destructive" };
  };

  const formatTime = (timeString: string) => {
    return new Date(`2000-01-01T${timeString}`).toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading oxygen services...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
        <div className="flex items-center justify-between p-4">
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={() => navigate("/dashboard")}
              className="text-white hover:bg-white/20"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div>
              <h1 className="text-xl font-semibold">Oxygen Refill Services</h1>
              <div className="flex items-center text-xs text-white/80">
                <MapPin className="h-3 w-3 mr-1" />
                <span>Trusted Hospital Services</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Emergency Notice */}
      <div className="bg-red-50 border-b border-red-200 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
            <Heart className="h-4 w-4 text-red-600" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-red-900">Medical Emergency</p>
            <p className="text-xs text-red-700">
              For immediate medical emergencies, call emergency services first.
            </p>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {providers.length === 0 ? (
          <Card className="p-8 text-center">
            <Heart className="h-16 w-16 text-muted-foreground/50 mx-auto mb-4" />
            <h3 className="font-semibold text-lg mb-2">No Oxygen Services Found</h3>
            <p className="text-muted-foreground mb-4">
              No hospitals offering oxygen refill services were found in your area.
            </p>
            <Button onClick={fetchOxygenProviders}>
              Try Again
            </Button>
          </Card>
        ) : (
          providers.map((provider, index) => {
            const distance = userLocation 
              ? calculateDistance(
                  userLocation.lat, 
                  userLocation.lng, 
                  parseFloat(provider.latitude) || 0, 
                  parseFloat(provider.longitude) || 0
                )
              : "Unknown";

            const operatingStatus = getCurrentOperatingStatus(provider);

            return (
              <motion.div
                key={provider.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-semibold text-lg">{provider.business_name}</h3>
                        {provider.is_verified && (
                          <Shield className="h-4 w-4 text-green-600" />
                        )}
                      </div>
                      
                      <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                        <MapPin className="h-3 w-3" />
                        <span>{provider.address}, {provider.city}</span>
                        {distance !== "Unknown" && (
                          <>
                            <span>•</span>
                            <span>{distance}</span>
                          </>
                        )}
                      </div>

                      <div className="flex items-center gap-4 text-sm mb-2">
                        <div className="flex items-center gap-1">
                          <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                          <span>{parseFloat(provider.average_rating).toFixed(1)}</span>
                          <span className="text-muted-foreground">
                            ({provider.total_reviews})
                          </span>
                        </div>
                        
                        <span className={`text-xs font-medium ${operatingStatus.color}`}>
                          {operatingStatus.status}
                        </span>
                      </div>

                      {provider.description && (
                        <p className="text-sm text-muted-foreground mb-2">
                          {provider.description}
                        </p>
                      )}
                    </div>
                    
                    <div className="w-12 h-12 rounded-lg bg-red-100 flex items-center justify-center text-red-600">
                      <Heart className="h-6 w-6" />
                    </div>
                  </div>

                  {/* Services Preview */}
                  {provider.services.length > 0 && (
                    <div className="mb-3">
                      <div className="flex gap-1 overflow-x-auto pb-2">
                        {provider.services.slice(0, 3).map(service => (
                          <span 
                            key={service.id}
                            className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-primary/10 text-primary font-medium whitespace-nowrap"
                          >
                            {service.name}
                          </span>
                        ))}
                        {provider.services.length > 3 && (
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-muted text-muted-foreground">
                            +{provider.services.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2 text-sm">
                      <Phone className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{provider.contact_number}</span>
                    </div>
                    
                    <div className="text-right">
                      <p className="text-xl font-bold text-primary">
                        {getOxygenServicePrice(provider)}
                      </p>
                      <p className="text-xs text-muted-foreground">Oxygen Refill</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <Button 
                      variant="outline"
                      className="w-full"
                      onClick={() => window.open(`tel:${provider.contact_number}`)}
                    >
                      <Phone className="h-4 w-4 mr-2" />
                      Call Now
                    </Button>
                    
                    <Button 
                      className="w-full bg-secondary hover:bg-secondary/90 text-white"
                      onClick={() => navigate(`/vendor/${provider.id}`)}
                    >
                      View Details
                    </Button>
                  </div>

                  {/* Operating Hours */}
                  {provider.operating_hours && provider.operating_hours.length > 0 && (
                    <div className="mt-3 pt-3 border-t">
                      <p className="text-xs text-muted-foreground">
                        <strong>Today's Hours:</strong> {
                          provider.operating_hours
                            .find(hours => hours.day === new Date().getDay())
                            ?.is_closed ? 'Closed' : 
                            `${formatTime(provider.operating_hours.find(hours => hours.day === new Date().getDay())?.opening_time || '')} - ${formatTime(provider.operating_hours.find(hours => hours.day === new Date().getDay())?.closing_time || '')}`
                        }
                      </p>
                    </div>
                  )}
                </Card>
              </motion.div>
            );
          })
        )}

        {/* Important Information */}
        <Card className="bg-blue-50 border-blue-200">
          <div className="p-4">
            <h4 className="font-semibold text-blue-900 mb-2">Important Information</h4>
            <ul className="text-sm text-blue-700 space-y-1 list-disc list-inside">
              <li>Bring valid medical prescription for oxygen refill</li>
              <li>Carry proper identification documents</li>
              <li>Check hospital requirements for cylinder exchange</li>
              <li>Emergency services may have different procedures</li>
              <li>Contact hospital in advance for specific requirements</li>
            </ul>
          </div>
        </Card>
      </div>

      <BottomNav />
    </div>
  );
};

export default OxygenServices;