import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, MapPin, Phone, Mail, Clock, Star, CheckCircle2, Globe, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import BottomNav from "@/components/BottomNav";
import Map from "@/components/Map";
import { useState, useEffect } from "react";
import { toast } from "sonner";
import { vendorsAPI } from "@/services/api";

// Interfaces
interface OperatingHours {
  id: number;
  day: number;
  opening_time: string;
  closing_time: string;
  is_closed: boolean;
}

interface VendorReview {
  id: number;
  customer_name: string;
  customer_username: string;
  rating: number;
  comment: string;
  created_at: string;
}

interface Vendor {
  id: string;
  business_name: string;
  business_type: string;
  description: string;
  latitude: number;
  longitude: number;
  address: string;
  city: string;
  country: string;
  contact_number: string;
  email: string;
  website: string;
  opening_hours: string;
  is_verified: boolean;
  is_active: boolean;
  average_rating: number;
  total_reviews: number;
  operating_hours: OperatingHours[];
  reviews: VendorReview[];
  owner_name: string;
  owner_email: string;
  delivery_radius_km?: number;
  min_order_amount?: number;
  delivery_fee?: number;
}

// Helper functions
const getServicesByBusinessType = (businessType: string): string[] => {
  switch (businessType) {
    case 'gas_station':
      return [
        "6kg Gas Cylinders",
        "13kg Gas Cylinders", 
        "Gas Refills",
        "New Cylinder Sales",
        "Free Delivery (orders above KSh 2000)",
        "Emergency Service Available"
      ];
    case 'mechanic':
      return [
        "Engine Repair",
        "Brake Services",
        "Oil Change",
        "Tire Replacement",
        "Electrical System Repair",
        "24/7 Emergency Service"
      ];
    case 'hospital':
      return [
        "Emergency Care",
        "Outpatient Services",
        "Laboratory Tests",
        "Pharmacy",
        "Ambulance Services",
        "24/7 Emergency Care"
      ];
    case 'roadside_assistance':
      return [
        "Tire Change",
        "Jump Start",
        "Fuel Delivery",
        "Lockout Service",
        "Towing",
        "24/7 Roadside Assistance"
      ];
    default:
      return [
        "Professional Services",
        "Quality Assurance",
        "Customer Support",
        "Emergency Services"
      ];
  }
};

const getTermsByBusinessType = (businessType: string): string[] => {
  switch (businessType) {
    case 'gas_station':
      return [
        "Payment on delivery accepted",
        "Refund available for defective cylinders within 24 hours",
        "Delivery within 2 hours for urgent orders",
        "Minimum order: KSh 500",
        "Cylinders must be returned within 30 days for deposit refund"
      ];
    case 'mechanic':
      return [
        "Payment upon completion of service",
        "Warranty on parts and labor",
        "Free estimates provided",
        "24/7 emergency service available",
        "Quality guaranteed on all repairs"
      ];
    case 'hospital':
      return [
        "Emergency cases prioritized",
        "Insurance accepted",
        "Payment plans available",
        "24/7 emergency services",
        "Confidentiality guaranteed"
      ];
    case 'roadside_assistance':
      return [
        "24/7 availability",
        "Response within 30 minutes",
        "Transparent pricing",
        "Multiple payment options",
        "Service area coverage clearly defined"
      ];
    default:
      return [
        "Professional service guaranteed",
        "Customer satisfaction priority",
        "Transparent pricing",
        "Quality assurance"
      ];
  }
};

const formatOperatingHours = (operatingHours: OperatingHours[]): string => {
  if (!operatingHours || operatingHours.length === 0) {
    return "24/7 Available";
  }

  const daysMap = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  
  // Group by time slots
  const timeSlots: { [key: string]: string[] } = {};
  
  operatingHours.forEach(hour => {
    if (hour.is_closed) {
      const key = 'Closed';
      if (!timeSlots[key]) timeSlots[key] = [];
      timeSlots[key].push(daysMap[hour.day]);
    } else {
      const timeKey = `${hour.opening_time} - ${hour.closing_time}`;
      if (!timeSlots[timeKey]) timeSlots[timeKey] = [];
      timeSlots[timeKey].push(daysMap[hour.day]);
    }
  });

  // Format the display string
  const formatted = Object.entries(timeSlots).map(([time, days]) => {
    if (days.length === 7) {
      return `Daily: ${time}`;
    } else if (days.length === 1) {
      return `${days[0]}: ${time}`;
    } else {
      return `${days[0]} - ${days[days.length - 1]}: ${time}`;
    }
  });

  return formatted.join('; ');
};

const ProviderDetail = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const [vendor, setVendor] = useState<Vendor | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Browse Services handler
  const handleBrowseServices = () => {
    if (!vendor) return;

    // Route based on business type
    switch (vendor.business_type) {
      case 'gas_station':
        navigate(`/services/gas/providers/${vendor.id}`, {
          state: { vendor }
        });
        break;
      case 'mechanic':
      case 'roadside_assistance':
        navigate(`/services/roadside/providers/${vendor.id}`, {
          state: { vendor }
        });
        break;
      case 'hospital':
        navigate(`/services/oxygen/providers/${vendor.id}`, {
          state: { vendor }
        });
        break;
      default:
        // Fallback to generic vendor page
        navigate(`/vendor/${vendor.id}`, {
          state: { vendor }
        });
        break;
    }
  };

  useEffect(() => {
    const fetchVendorDetails = async () => {
      try {
        setLoading(true);
        setError(null);
        
        console.log("Fetching vendor with ID:", id);
        
        // Use the vendorsAPI service
        const response = await vendorsAPI.getVendor(Number(id));
        console.log("Vendor API response:", response);
        console.log("Vendor data:", response.data);
        
        setVendor(response.data);
        
      } catch (err: any) {
        console.error("Error fetching vendor details:", err);
        
        // Detailed error logging
        if (err.response) {
          console.error("Response status:", err.response.status);
          console.error("Response data:", err.response.data);
        }
        
        if (err.response?.status === 404) {
          setError("Vendor not found");
          toast.error("Vendor not found. It may have been removed or doesn't exist.");
        } else if (err.response?.status === 403) {
          setError("Access denied");
          toast.error("You don't have permission to view this vendor.");
        } else if (!err.response) {
          setError("Network error");
          toast.error("Cannot connect to server. Please check your internet connection.");
        } else {
          setError(`Server error: ${err.response.status}`);
          toast.error("Failed to load vendor details. Please try again.");
        }
        
        // Fallback to mock data for demo
        console.log("Using mock data as fallback");
        setVendor(getMockVendorData());
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchVendorDetails();
    } else {
      setError("No vendor ID provided");
      setLoading(false);
    }
  }, [id]);

  // Mock data fallback
  const getMockVendorData = (): Vendor => ({
    id: id || "1",
    business_name: "Nairobi Gas Center",
    business_type: "gas_station",
    description: "Your trusted partner for quality gas products and reliable service. We provide safe and efficient gas solutions for homes and businesses.",
    latitude: -1.286389,
    longitude: 36.817223,
    address: "Moi Avenue, Nairobi CBD",
    city: "Nairobi",
    country: "Kenya",
    contact_number: "+254712345678",
    email: "info@nairobigas.com",
    website: "https://nairobigas.com",
    opening_hours: "Mon-Sun: 6:00 AM - 10:00 PM",
    is_verified: true,
    is_active: true,
    average_rating: 4.5,
    total_reviews: 124,
    operating_hours: [
      { id: 1, day: 0, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 2, day: 1, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 3, day: 2, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 4, day: 3, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 5, day: 4, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 6, day: 5, opening_time: "06:00", closing_time: "22:00", is_closed: false },
      { id: 7, day: 6, opening_time: "08:00", closing_time: "20:00", is_closed: false }
    ],
    reviews: [
      {
        id: 1,
        customer_name: "John Kamau",
        customer_username: "johnk",
        rating: 5,
        comment: "Excellent service and fast delivery! The gas quality is top-notch.",
        created_at: "2024-01-15T10:30:00Z"
      },
      {
        id: 2,
        customer_name: "Mary Wanjiku",
        customer_username: "maryw",
        rating: 4,
        comment: "Good prices and reliable service. Will definitely order again.",
        created_at: "2024-01-10T14:20:00Z"
      }
    ],
    owner_name: "David Mwangi",
    owner_email: "david@nairobigas.com",
    delivery_radius_km: 10,
    min_order_amount: 500,
    delivery_fee: 200
  });

  // Get appropriate emoji based on business type
  const getBusinessEmoji = (businessType: string) => {
    switch (businessType) {
      case 'gas_station': return '🔥';
      case 'mechanic': return '🔧';
      case 'hospital': return '🏥';
      case 'roadside_assistance': return '🛟';
      default: return '🏢';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20">
        <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
          <div className="flex items-center gap-3 p-4">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={() => navigate(-1)}
              className="text-white hover:bg-white/20"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <h1 className="text-xl font-semibold">Vendor Details</h1>
          </div>
        </header>
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
            <p className="text-muted-foreground">Loading vendor details...</p>
          </div>
        </div>
        <BottomNav />
      </div>
    );
  }

  if (error && !vendor) {
    return (
      <div className="min-h-screen bg-background pb-20">
        <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
          <div className="flex items-center gap-3 p-4">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={() => navigate(-1)}
              className="text-white hover:bg-white/20"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <h1 className="text-xl font-semibold">Vendor Details</h1>
          </div>
        </header>
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <p className="text-destructive mb-4">{error}</p>
            <Button onClick={() => window.location.reload()}>
              Try Again
            </Button>
          </div>
        </div>
        <BottomNav />
      </div>
    );
  }

  // Use vendor data (either from API or mock)
  const services = getServicesByBusinessType(vendor!.business_type);
  const termsOfService = getTermsByBusinessType(vendor!.business_type);
  const formattedHours = vendor!.operating_hours 
    ? formatOperatingHours(vendor!.operating_hours) 
    : vendor!.opening_hours || "24/7 Available";

  return (
    <div className="min-h-screen bg-background pb-20">
      {/* Header */}
      <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
        <div className="flex items-center gap-3 p-4">
          <Button 
            variant="ghost" 
            size="icon" 
            onClick={() => navigate(-1)}
            className="text-white hover:bg-white/20"
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-semibold">Vendor Details</h1>
        </div>
      </header>

      <div className="space-y-4">
        {/* Vendor Header */}
        <Card className="rounded-none border-x-0">
          <div className="p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <h2 className="text-2xl font-bold">{vendor!.business_name}</h2>
                  {vendor!.is_verified && (
                    <Badge variant="secondary" className="bg-green-100 text-green-800">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Verified
                    </Badge>
                  )}
                  {!vendor!.is_active && (
                    <Badge variant="secondary" className="bg-red-100 text-red-800">
                      Inactive
                    </Badge>
                  )}
                </div>
                <p className="text-muted-foreground capitalize">
                  {vendor!.business_type.replace('_', ' ')}
                </p>
              </div>
              <div className="text-4xl">{getBusinessEmoji(vendor!.business_type)}</div>
            </div>
            
            <div className="flex items-center gap-2 mb-3">
              <Star className="h-5 w-5 fill-yellow-500 text-yellow-500" />
              <span className="font-semibold">{vendor!.average_rating}</span>
              <span className="text-muted-foreground text-sm">
                ({vendor!.total_reviews} reviews)
              </span>
            </div>

            <div className="flex items-center gap-2 text-muted-foreground mb-2">
              <MapPin className="h-4 w-4" />
              <span className="text-sm">{vendor!.address}, {vendor!.city}, {vendor!.country}</span>
            </div>

            <p className="text-sm text-muted-foreground mt-3">
              {vendor!.description}
            </p>
          </div>
        </Card>

        {/* Location Map */}
        {vendor!.latitude && vendor!.longitude && (
          <Card className="rounded-none border-x-0 overflow-hidden">
            <div className="h-[250px]">
              <Map 
                providers={[{
                  id: Number(vendor!.id),
                  name: vendor!.business_name,
                  location: vendor!.address,
                  price: "View Services",
                  coords: [Number(vendor!.latitude), Number(vendor!.longitude)] as [number, number]
                }]} 
                userLocation={null}
              />
            </div>
          </Card>
        )}

        {/* Contact Information */}
        <Card className="mx-4">
          <div className="p-4">
            <h3 className="font-semibold mb-3">Contact Information</h3>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <MapPin className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">Address</p>
                  <p className="text-sm text-muted-foreground">{vendor!.address}</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <Phone className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">Phone</p>
                  <a href={`tel:${vendor!.contact_number}`} className="text-sm text-primary">
                    {vendor!.contact_number}
                  </a>
                </div>
              </div>

              {vendor!.email && (
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                    <Mail className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Email</p>
                    <a href={`mailto:${vendor!.email}`} className="text-sm text-primary">
                      {vendor!.email}
                    </a>
                  </div>
                </div>
              )}

              {vendor!.website && (
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                    <Globe className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Website</p>
                    <a 
                      href={vendor!.website} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-sm text-primary"
                    >
                      {vendor!.website}
                    </a>
                  </div>
                </div>
              )}

              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <Clock className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">Opening Hours</p>
                  <p className="text-sm text-muted-foreground">{formattedHours}</p>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Services Offered */}
        <Card className="mx-4">
          <div className="p-4">
            <h3 className="font-semibold mb-3">Services Offered</h3>
            <div className="space-y-2">
              {services.map((service, index) => (
                <div key={index} className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-primary flex-shrink-0" />
                  <span className="text-sm">{service}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Recent Reviews */}
        {vendor!.reviews && vendor!.reviews.length > 0 && (
          <Card className="mx-4">
            <div className="p-4">
              <h3 className="font-semibold mb-3">Recent Reviews</h3>
              <div className="space-y-3">
                {vendor!.reviews.slice(0, 3).map((review) => (
                  <div key={review.id} className="border-b pb-3 last:border-0 last:pb-0">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="flex items-center gap-1">
                        {[...Array(5)].map((_, i) => (
                          <Star
                            key={i}
                            className={`h-3 w-3 ${
                              i < review.rating
                                ? 'fill-yellow-500 text-yellow-500'
                                : 'fill-gray-200 text-gray-200'
                            }`}
                          />
                        ))}
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(review.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-sm font-medium mb-1">{review.customer_name}</p>
                    <p className="text-sm text-muted-foreground">{review.comment}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        )}

        {/* Terms of Service */}
        <Card className="mx-4 mb-4">
          <div className="p-4">
            <h3 className="font-semibold mb-3">Terms of Service</h3>
            <div className="space-y-2">
              {termsOfService.map((term, index) => (
                <div key={index} className="flex items-start gap-2">
                  <Badge variant="outline" className="mt-0.5 flex-shrink-0">
                    {index + 1}
                  </Badge>
                  <span className="text-sm">{term}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Action Buttons */}
        <div className="px-4 pb-4 space-y-2">
          <Button 
            className="w-full bg-secondary hover:bg-secondary/90"
            size="lg"
            onClick={handleBrowseServices}
          >
            Browse Services
          </Button>
          <div className="grid grid-cols-2 gap-2">
            <Button 
              variant="outline"
              className="w-full"
              onClick={() => window.open(`tel:${vendor!.contact_number}`)}
            >
              <Phone className="h-4 w-4 mr-2" />
              Call
            </Button>
            <Button 
              variant="outline"
              className="w-full"
              onClick={() => window.open(`https://wa.me/${vendor!.contact_number.replace('+', '')}`, '_blank')}
            >
              💬 WhatsApp
            </Button>
          </div>
        </div>
      </div>

      <BottomNav />
    </div>
  );
};

export default ProviderDetail;