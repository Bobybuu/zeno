import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, MapPin, Wrench, Fuel, Truck, Star, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useToast } from "@/components/ui/use-toast";
import Map from "@/components/Map";
import BottomNav from "@/components/BottomNav";
import { motion } from "framer-motion";

interface ServiceProvider {
  id: number;
  business_name: string;
  business_type: string;
  description: string;
  address: string;
  city: string;
  contact_number: string;
  average_rating: string;
  total_reviews: number;
  latitude: string;
  longitude: string;
  is_verified: boolean;
  services: Array<{
    id: number;
    name: string;
    description: string;
    price: string;
    available: boolean;
  }>;
}

interface ServiceCategory {
  id: string;
  title: string;
  icon: any;
  color: string;
  business_types: string[];
}

interface ApiResponse {
  results?: ServiceProvider[];
  count?: number;
  next?: string;
  previous?: string;
}

const RoadsideServices = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [providers, setProviders] = useState<ServiceProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);

  const serviceCategories: ServiceCategory[] = [
    {
      id: "mechanical",
      title: "Mechanical Services",
      icon: Wrench,
      color: "bg-blue-500",
      business_types: ['mechanic', 'roadside_assistance']
    },
    {
      id: "fuel",
      title: "Fuel Refill",
      icon: Fuel,
      color: "bg-green-500",
      business_types: ['gas_station', 'roadside_assistance']
    },
    {
      id: "towing",
      title: "Towing Services",
      icon: Truck,
      color: "bg-red-500",
      business_types: ['roadside_assistance']
    }
  ];

  useEffect(() => {
    getUserLocation();
    fetchRoadsideProviders();
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

  const fetchRoadsideProviders = async () => {
    try {
      const token = localStorage.getItem('access_token');
      
      // Get all roadside-related business types
      const businessTypes = ['mechanic', 'roadside_assistance', 'gas_station'];
      
      const baseUrl = 'https://api.zenoservices.co.ke/api';
      const params = new URLSearchParams({
        business_type__in: businessTypes.join(',')
      });

      // Add location parameters if available
      if (userLocation) {
        params.append('lat', userLocation.lat.toString());
        params.append('lng', userLocation.lng.toString());
        params.append('radius', '20'); // 20km radius
      }

      console.log('Fetching roadside providers from:', `${baseUrl}/vendors/?${params}`);

      const response = await fetch(`${baseUrl}/vendors/?${params}`, {
        headers: {
          'Authorization': token ? `Bearer ${token}` : '',
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data: ApiResponse | ServiceProvider[] = await response.json();
        console.log('Fetched providers data:', data);
        
        // FIXED: Handle different response formats
        let providersData: ServiceProvider[] = [];
        
        if (Array.isArray(data)) {
          // If response is directly an array
          providersData = data;
        } else if (data && typeof data === 'object' && 'results' in data) {
          // If response is paginated with results field
          providersData = data.results || [];
        } else if (data && typeof data === 'object') {
          // If response is a single object, wrap it in array
          providersData = [data as ServiceProvider];
        }
        
        console.log('Processed providers:', providersData);
        setProviders(providersData);
      } else if (response.status === 404) {
        // If the main vendors endpoint fails, try alternative endpoints
        await fetchAlternativeEndpoints();
      } else {
        throw new Error(`Failed to fetch roadside providers: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error fetching roadside providers:', error);
      // Try alternative endpoints as fallback
      await fetchAlternativeEndpoints();
    } finally {
      setLoading(false);
    }
  };

  // Fallback method to try different API endpoints
  const fetchAlternativeEndpoints = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const businessTypes = ['mechanic', 'roadside_assistance', 'gas_station'];
      
      // Try different possible endpoints
      const endpoints = [
        'https://api.zenoservices.co.ke/api/vendors/vendors/',
        'https://api.zenoservices.co.ke/api/vendors/',
        'https://api.zenoservices.co.ke/api/services/vendors/'
      ];

      for (const endpoint of endpoints) {
        try {
          const params = new URLSearchParams({
            business_type__in: businessTypes.join(',')
          });

          console.log('Trying alternative endpoint:', `${endpoint}?${params}`);

          const response = await fetch(`${endpoint}?${params}`, {
            headers: {
              'Authorization': token ? `Bearer ${token}` : '',
              'Content-Type': 'application/json'
            }
          });

          if (response.ok) {
            const data: ApiResponse | ServiceProvider[] = await response.json();
            console.log('Success with endpoint:', endpoint, data);
            
            let providersData: ServiceProvider[] = [];
            
            if (Array.isArray(data)) {
              providersData = data;
            } else if (data && typeof data === 'object' && 'results' in data) {
              providersData = data.results || [];
            } else if (data && typeof data === 'object') {
              providersData = [data as ServiceProvider];
            }
            
            setProviders(providersData);
            return; // Success, exit the function
          }
        } catch (error) {
          console.warn(`Endpoint ${endpoint} failed:`, error);
          continue; // Try next endpoint
        }
      }

      // If all endpoints fail, show mock data for demonstration
      console.log('All API endpoints failed, using mock data');
      setProviders(getMockProviders());
      toast({
        title: "Demo Mode",
        description: "Showing demo data. Real providers will load when API is available.",
        variant: "default"
      });

    } catch (error) {
      console.error('All alternative endpoints failed:', error);
      toast({
        title: "Error",
        description: "Failed to load roadside services. Please try again later.",
        variant: "destructive"
      });
    }
  };

  // Mock data for demonstration when API is unavailable
  const getMockProviders = (): ServiceProvider[] => [
    {
      id: 1,
      business_name: "Nairobi Auto Repair",
      business_type: "mechanic",
      description: "24/7 mechanical services and roadside assistance",
      address: "Mombasa Road, Nairobi",
      city: "Nairobi",
      contact_number: "+254712345678",
      average_rating: "4.5",
      total_reviews: 124,
      latitude: "-1.286389",
      longitude: "36.817223",
      is_verified: true,
      services: [
        {
          id: 1,
          name: "Emergency Towing",
          description: "Vehicle towing services",
          price: "2500",
          available: true
        },
        {
          id: 2,
          name: "Tire Change",
          description: "Flat tire replacement",
          price: "800",
          available: true
        }
      ]
    },
    {
      id: 2,
      business_name: "Shell Station Westlands",
      business_type: "gas_station",
      description: "Fuel station with roadside assistance",
      address: "Westlands, Nairobi",
      city: "Nairobi",
      contact_number: "+254723456789",
      average_rating: "4.2",
      total_reviews: 89,
      latitude: "-1.265590",
      longitude: "36.806360",
      is_verified: true,
      services: [
        {
          id: 3,
          name: "Fuel Delivery",
          description: "Emergency fuel delivery",
          price: "1500",
          available: true
        }
      ]
    },
    {
      id: 3,
      business_name: "City Tow Services",
      business_type: "roadside_assistance",
      description: "Professional towing and recovery services",
      address: "Thika Road, Nairobi",
      city: "Nairobi",
      contact_number: "+254734567890",
      average_rating: "4.7",
      total_reviews: 156,
      latitude: "-1.238270",
      longitude: "36.830270",
      is_verified: true,
      services: [
        {
          id: 4,
          name: "Heavy Duty Towing",
          description: "Towing for trucks and large vehicles",
          price: "5000",
          available: true
        },
        {
          id: 5,
          name: "Light Towing",
          description: "Towing for cars and small vehicles",
          price: "2000",
          available: true
        }
      ]
    }
  ];

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

  const getServicePrice = (provider: ServiceProvider): string => {
    if (!provider.services || provider.services.length === 0) return "Contact for pricing";
    
    const prices = provider.services
      .map(s => parseFloat(s.price))
      .filter(price => !isNaN(price));
    
    if (prices.length === 0) return "Contact for pricing";
    
    const minPrice = Math.min(...prices);
    return `From KSh ${minPrice.toLocaleString()}`;
  };

  const getFilteredProviders = () => {
    if (!selectedService) return providers;
    
    const category = serviceCategories.find(cat => cat.id === selectedService);
    if (!category) return providers;
    
    return providers.filter(provider => 
      category.business_types.includes(provider.business_type)
    );
  };

  const getProviderCoordinates = (provider: ServiceProvider): [number, number] => {
    // FIXED: Handle invalid coordinates
    const lat = parseFloat(provider.latitude);
    const lng = parseFloat(provider.longitude);
    
    if (isNaN(lat) || isNaN(lng)) {
      // Default to Nairobi coordinates if invalid
      return [36.817223, -1.286389];
    }
    
    return [lng, lat]; // Note: longitude first for Mapbox
  };

  // FIXED: Added proper error handling for map providers
  const getMapProviders = () => {
    const filteredProviders = getFilteredProviders();
    
    if (!Array.isArray(filteredProviders)) {
      console.error('Filtered providers is not an array:', filteredProviders);
      return [];
    }
    
    return filteredProviders.map(provider => {
      try {
        return {
          id: provider.id,
          name: provider.business_name,
          location: provider.address,
          coords: getProviderCoordinates(provider),
          price: getServicePrice(provider),
          rating: parseFloat(provider.average_rating) || 0,
          distance: userLocation 
            ? calculateDistance(
                userLocation.lat, 
                userLocation.lng, 
                parseFloat(provider.latitude) || 0, 
                parseFloat(provider.longitude) || 0
              )
            : "Unknown"
        };
      } catch (error) {
        console.error('Error processing provider for map:', provider, error);
        return null;
      }
    }).filter(Boolean); // Remove any null entries
  };

  const refreshProviders = () => {
    setLoading(true);
    fetchRoadsideProviders();
  };

  // FIXED: Added safe provider count calculation
  const getProviderCount = (businessTypes: string[]) => {
    if (!Array.isArray(providers)) return 0;
    return providers.filter(p => businessTypes.includes(p.business_type)).length;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading roadside services...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      {/* Header */}
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
              <h1 className="text-xl font-semibold">Roadside Services</h1>
              <div className="flex items-center text-xs text-white/80">
                <MapPin className="h-3 w-3 mr-1" />
                <span>Emergency assistance near you</span>
              </div>
            </div>
          </div>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={refreshProviders}
            className="text-white hover:bg-white/20"
          >
            Refresh
          </Button>
        </div>
      </header>

      {/* Map Section */}
      <div className="h-[300px] relative">
        <Map providers={getMapProviders()} />
      </div>

      {/* Service Categories */}
      <div className="p-4">
        <h2 className="text-lg font-semibold mb-3">Select Service Type</h2>
        <div className="grid grid-cols-3 gap-3 mb-6">
          {serviceCategories.map((service) => {
            const Icon = service.icon;
            const providerCount = getProviderCount(service.business_types);

            return (
              <motion.div
                key={service.id}
                whileTap={{ scale: 0.95 }}
              >
                <Card
                  className={`p-4 cursor-pointer transition-all ${
                    selectedService === service.id 
                      ? 'ring-2 ring-secondary shadow-lg' 
                      : 'hover:shadow-md'
                  }`}
                  onClick={() => setSelectedService(
                    selectedService === service.id ? null : service.id
                  )}
                >
                  <div className="flex flex-col items-center text-center">
                    <div className={`w-12 h-12 rounded-full ${service.color} flex items-center justify-center mb-2`}>
                      <Icon className="h-6 w-6 text-white" />
                    </div>
                    <span className="text-sm font-medium">{service.title}</span>
                    <span className="text-xs text-muted-foreground mt-1">
                      {providerCount} providers
                    </span>
                  </div>
                </Card>
              </motion.div>
            );
          })}
        </div>

        {/* Provider List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold">
              {selectedService 
                ? serviceCategories.find(s => s.id === selectedService)?.title 
                : "All Roadside Providers"}
            </h3>
            <span className="text-sm text-muted-foreground">
              {Array.isArray(providers) ? getFilteredProviders().length : 0} providers
            </span>
          </div>

          {!Array.isArray(providers) || getFilteredProviders().length === 0 ? (
            <Card className="p-8 text-center">
              <Wrench className="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
              <h3 className="font-semibold mb-2">No Providers Found</h3>
              <p className="text-muted-foreground mb-4">
                {selectedService 
                  ? `No ${serviceCategories.find(s => s.id === selectedService)?.title.toLowerCase()} available in your area`
                  : "No roadside service providers available in your area"
                }
              </p>
              <Button onClick={refreshProviders} variant="outline">
                Try Again
              </Button>
            </Card>
          ) : (
            getFilteredProviders().map((provider, index) => {
              const distance = userLocation 
                ? calculateDistance(
                    userLocation.lat, 
                    userLocation.lng, 
                    parseFloat(provider.latitude) || 0, 
                    parseFloat(provider.longitude) || 0
                  )
                : "Unknown";

              return (
                <motion.div
                  key={provider.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <Card 
                    className="p-4 cursor-pointer hover:shadow-lg transition-all"
                    onClick={() => navigate(`/vendor/${provider.id}`)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-semibold">{provider.business_name}</h4>
                          {provider.is_verified && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              Verified
                            </span>
                          )}
                        </div>
                        
                        <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                          <MapPin className="h-3 w-3" />
                          <span>{provider.city}</span>
                          <span>•</span>
                          <span>{distance}</span>
                        </div>

                        <div className="flex items-center gap-2 text-sm mb-2">
                          <div className="flex items-center gap-1">
                            <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                            <span>{(parseFloat(provider.average_rating) || 0).toFixed(1)}</span>
                            <span className="text-muted-foreground">
                              ({provider.total_reviews || 0})
                            </span>
                          </div>
                        </div>

                        <p className="text-primary font-semibold">
                          {getServicePrice(provider)}
                        </p>

                        {provider.services && provider.services.length > 0 && (
                          <div className="flex gap-1 mt-2 overflow-x-auto">
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
                        )}
                      </div>
                      
                      <Button 
                        className="bg-secondary hover:bg-secondary/90 text-white ml-2"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          window.open(`tel:${provider.contact_number}`);
                        }}
                      >
                        Contact
                      </Button>
                    </div>
                  </Card>
                </motion.div>
              );
            })
          )}
        </div>

        {/* Emergency Services Notice */}
        <Card className="mt-6 bg-red-50 border-red-200">
          <div className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
                <Truck className="h-5 w-5 text-red-600" />
              </div>
              <div className="flex-1">
                <h4 className="font-semibold text-red-900">24/7 Emergency Services</h4>
                <p className="text-sm text-red-700">
                  Need immediate assistance? Contact providers directly for emergency roadside help.
                </p>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <BottomNav />
    </div>
  );
};

export default RoadsideServices;