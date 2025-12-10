import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { MapPin, Search, Menu, Bell, User, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import ServiceCard from "@/components/ServiceCard";
import BottomNav from "@/components/BottomNav";
import { motion } from "framer-motion";
import { safeGasProductsAPI, vendorsAPI } from "@/services/api";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

interface GasProduct {
  id: number;
  name: string;
  gas_type: string;
  cylinder_size: string;
  price_with_cylinder: number;
  price_without_cylinder: number;
  vendor_name: string;
  vendor_city: string;
  vendor_latitude?: number;
  vendor_longitude?: number;
  is_available: boolean;
  in_stock: boolean;
  stock_quantity: number;
  min_stock_alert: number;
}

interface Vendor {
  id: number;
  business_name: string;
  business_type: string;
  average_rating: number;
  total_reviews: number;
  address: string;
  city: string;
  contact_number: string;
  latitude?: number;
  longitude?: number;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const { currentUser } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const [gasProducts, setGasProducts] = useState<GasProduct[]>([]);
  const [recentVendors, setRecentVendors] = useState<Vendor[]>([]);
  const [loading, setLoading] = useState(true);
  const [userLocation, setUserLocation] = useState<[number, number] | null>(null);

  const services = [
    {
      id: "gas",
      title: "Gas",
      description: "Find gas sellers near you",
      icon: "🔥",
      color: "bg-orange-500",
      route: "/services/gas"
    },
    {
      id: "roadside",
      title: "Roadside Services",
      description: "Mechanical, Fuel, Towing",
      icon: "🚗",
      color: "bg-blue-500",
      route: "/services/roadside"
    },
    {
      id: "oxygen",
      title: "Trusted Oxygen Refill",
      description: "Hospital oxygen services",
      icon: "🏥",
      color: "bg-red-500",
      route: "/services/oxygen"
    }
  ];

  // Get user's current location
  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setUserLocation([latitude, longitude]);
          console.log("User location set:", latitude, longitude);
        },
        (error) => {
          console.error("Error getting location:", error);
          toast.info("Enable location for better results");
        },
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 60000
        }
      );
    }
  }, []);

  // Fetch dashboard data
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        console.log("Fetching dashboard data...");

        // Prepare filters for gas products
        const gasFilters: any = {
          is_available: true,
          vendor__is_verified: true
        };

        // Add location filters only if we have valid coordinates
        if (userLocation && userLocation[0] && userLocation[1]) {
          gasFilters.lat = userLocation[0];
          gasFilters.lng = userLocation[1];
          gasFilters.radius = 10;
          console.log("Using location filters:", gasFilters);
        } else {
          console.log("No location available, fetching all available products");
        }

        // Use Promise.allSettled to handle individual API failures gracefully
        const [gasResponse, vendorsResponse] = await Promise.allSettled([
          safeGasProductsAPI.getGasProducts(gasFilters),
          vendorsAPI.getVendors({ 
            business_type: 'gas_station',
            is_verified: true,
            is_active: true 
          })
        ]);

        console.log("API responses:", { gasResponse, vendorsResponse });

        // Handle gas products response
        if (gasResponse.status === 'fulfilled') {
          const gasData = gasResponse.value;
          console.log("Gas products API response:", gasData);
          
          // Handle different response formats (array vs paginated)
          const products = Array.isArray(gasData) ? gasData : 
                          gasData.results ? gasData.results : 
                          gasData.data ? gasData.data : [];
          
          console.log("Processed gas products:", products);
          setGasProducts(products.slice(0, 4));
        } else {
          console.error("Failed to fetch gas products:", gasResponse.reason);
          // Use fallback mock data for gas products
          setGasProducts(getMockGasProducts());
          toast.warning("Using demo gas products data");
        }

        // Handle vendors response
        if (vendorsResponse.status === 'fulfilled') {
          const vendorsData = vendorsResponse.value.data || vendorsResponse.value;
          console.log("Vendors API response:", vendorsData);
          
          // Handle different response formats
          const vendors = Array.isArray(vendorsData) ? vendorsData : 
                         vendorsData.results ? vendorsData.results : [];
          
          console.log("Processed vendors:", vendors);
          setRecentVendors(vendors.slice(0, 4));
        } else {
          console.error("Failed to fetch vendors:", vendorsResponse.reason);
          // Use fallback mock data for vendors
          setRecentVendors(getMockVendors());
          toast.warning("Using demo vendors data");
        }

      } catch (error: any) {
        console.error("Error in fetchDashboardData:", error);
        
        // Use comprehensive fallback data
        setGasProducts(getMockGasProducts());
        setRecentVendors(getMockVendors());
        
        toast.error("Using demo data - API connection failed");
        
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, [userLocation]);

  // Mock data fallbacks
  const getMockGasProducts = (): GasProduct[] => [
    {
      id: 1,
      name: "Pro Gas LPG",
      gas_type: "lpg",
      cylinder_size: "13kg",
      price_with_cylinder: 3500,
      price_without_cylinder: 2800,
      vendor_name: "Nairobi Gas Center",
      vendor_city: "Nairobi",
      vendor_latitude: -1.286389,
      vendor_longitude: 36.817223,
      is_available: true,
      in_stock: true,
      stock_quantity: 50,
      min_stock_alert: 5
    },
    {
      id: 2,
      name: "K-Gas LPG",
      gas_type: "lpg",
      cylinder_size: "6kg",
      price_with_cylinder: 1800,
      price_without_cylinder: 1500,
      vendor_name: "Westlands Gas Shop",
      vendor_city: "Nairobi",
      vendor_latitude: -1.266667,
      vendor_longitude: 36.800000,
      is_available: true,
      in_stock: true,
      stock_quantity: 30,
      min_stock_alert: 3
    },
    {
      id: 3,
      name: "Safe Gas LPG",
      gas_type: "lpg",
      cylinder_size: "22kg",
      price_with_cylinder: 5200,
      price_without_cylinder: 4500,
      vendor_name: "Kilimani Gas Depot",
      vendor_city: "Nairobi",
      vendor_latitude: -1.300000,
      vendor_longitude: 36.783333,
      is_available: true,
      in_stock: true,
      stock_quantity: 20,
      min_stock_alert: 2
    },
    {
      id: 4,
      name: "Quick Gas LPG",
      gas_type: "lpg",
      cylinder_size: "13kg",
      price_with_cylinder: 3400,
      price_without_cylinder: 2700,
      vendor_name: "CBD Gas Station",
      vendor_city: "Nairobi",
      vendor_latitude: -1.283333,
      vendor_longitude: 36.816667,
      is_available: true,
      in_stock: true,
      stock_quantity: 40,
      min_stock_alert: 4
    }
  ];

  const getMockVendors = (): Vendor[] => [
    {
      id: 1,
      business_name: "Nairobi Gas Center",
      business_type: "gas_station",
      average_rating: 4.5,
      total_reviews: 124,
      address: "Moi Avenue, Nairobi CBD",
      city: "Nairobi",
      contact_number: "+254712345678",
      latitude: -1.286389,
      longitude: 36.817223
    },
    {
      id: 2,
      business_name: "Westlands Gas Shop",
      business_type: "gas_station",
      average_rating: 4.2,
      total_reviews: 89,
      address: "Westlands Mall, Nairobi",
      city: "Nairobi",
      contact_number: "+254723456789",
      latitude: -1.266667,
      longitude: 36.800000
    },
    {
      id: 3,
      business_name: "Kilimani Gas Depot",
      business_type: "gas_station",
      average_rating: 4.7,
      total_reviews: 156,
      address: "Argwings Kodhek Road, Kilimani",
      city: "Nairobi",
      contact_number: "+254734567890",
      latitude: -1.300000,
      longitude: 36.783333
    },
    {
      id: 4,
      business_name: "CBD Gas Station",
      business_type: "gas_station",
      average_rating: 4.0,
      total_reviews: 67,
      address: "Tom Mboya Street, Nairobi",
      city: "Nairobi",
      contact_number: "+254745678901",
      latitude: -1.283333,
      longitude: 36.816667
    }
  ];

  const calculateDistance = (lat1: number, lon1: number, lat2?: number, lon2?: number): string => {
    if (!lat1 || !lon1 || !lat2 || !lon2) return "Nearby";
    
    try {
      const R = 6371; // Earth's radius in km
      const dLat = (lat2 - lat1) * Math.PI / 180;
      const dLon = (lon2 - lon1) * Math.PI / 180;
      const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      const distance = R * c;
      
      return distance < 1 ? `${Math.round(distance * 1000)}m` : `${distance.toFixed(1)}km`;
    } catch (error) {
      console.error("Error calculating distance:", error);
      return "Nearby";
    }
  };

  const formatPrice = (price: number) => {
    return `KSh ${price.toLocaleString()}`;
  };

  const getUserInitials = () => {
    if (!currentUser) return "U";
    if (currentUser.first_name && currentUser.last_name) {
      return `${currentUser.first_name[0]}${currentUser.last_name[0]}`.toUpperCase();
    }
    return currentUser.username?.[0]?.toUpperCase() || "U";
  };

  const getUserDisplayName = () => {
    if (!currentUser) return "User";
    if (currentUser.first_name && currentUser.last_name) {
      return `${currentUser.first_name} ${currentUser.last_name}`;
    }
    return currentUser.username || "User";
  };

  const handleProductClick = (product: GasProduct) => {
    navigate(`/gas-product/${product.id}`, { state: { product } });
  };

  const handleVendorClick = (vendor: Vendor) => {
    navigate(`/vendor/${vendor.id}`);
  };

  const handleSearch = () => {
    if (searchQuery.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Loading dashboard...</p>
          <p className="text-sm text-muted-foreground mt-2">
            {userLocation ? "Using your location" : "Location not available"}
          </p>
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
            
            <div>
              <h1 className="text-xl font-bold">zeno</h1>
              <div className="flex items-center text-xs text-white/80">
                <MapPin className="h-3 w-3 mr-1" />
                <span>
                  {userLocation ? "Current Location" : "Enable location for better results"}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Avatar className="h-8 w-8 cursor-pointer" onClick={() => navigate("/account")}>
              <AvatarFallback className="bg-secondary text-white">
                {getUserInitials()}
              </AvatarFallback>
            </Avatar>
          </div>
        </div>
        
        {/* Welcome Message */}
        <div className="px-4 pb-3">
          <h2 className="text-lg font-semibold">
            Welcome back, {getUserDisplayName()}! 👋
          </h2>
          <p className="text-sm text-white/80 mt-1">
            What service do you need today?
          </p>
        </div>

        {/* Search Bar */}
        
      </header>

      {/* Service Categories */}
      <section className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Our Services</h2>
          <span className="text-sm text-muted-foreground">Trusted & Reliable</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {services.map((service, index) => (
            <motion.div
              key={service.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <ServiceCard
                {...service}
                onClick={() => navigate(service.route)}
              />
            </motion.div>
          ))}
        </div>
      </section>

{/* Gas Products Section */}
<section className="p-4">
  <div className="flex items-center justify-between mb-4">
    <h2 className="text-lg font-semibold">Gas Products Near You</h2>
    <Button 
      variant="link" 
      className="text-secondary p-0 h-auto font-semibold"
      onClick={() => navigate("/services/gas")}
    >
      View All
    </Button>
  </div>

  {gasProducts.length === 0 ? (
    <Card className="p-8 text-center">
      <div className="text-6xl mb-4">🔥</div>
      <h3 className="text-lg font-semibold mb-2">No gas products found</h3>
      <p className="text-muted-foreground mb-4">
        {userLocation 
          ? "No gas products available in your area yet" 
          : "Enable location services to see nearby products"
        }
      </p>
      <Button onClick={() => navigate("/services/gas")}>
        Browse All Gas Products
      </Button>
    </Card>
  ) : (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {gasProducts.map((product, index) => (
        <motion.div
          key={product.id}
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: index * 0.05 }}
        >
          <Card 
            className="p-3 cursor-pointer hover:shadow-lg transition-all duration-300 hover:-translate-y-1 border-2 border-transparent hover:border-orange-200"
            onClick={() => navigate(`/services/gas/${product.id}`)} // Navigate to gas listing page
          >
            <div className="aspect-square bg-gradient-to-br from-orange-100 to-orange-50 rounded-lg mb-2 flex items-center justify-center">
              <span className="text-3xl">🔥</span>
            </div>
            <h3 className="font-medium text-sm truncate">{product.name}</h3>
            <p className="text-xs text-muted-foreground truncate">
              {product.cylinder_size} • {product.vendor_name}
            </p>
            {userLocation && product.vendor_latitude && product.vendor_longitude && (
              <p className="text-xs text-muted-foreground mt-1">
                {calculateDistance(
                  userLocation[0], 
                  userLocation[1], 
                  product.vendor_latitude, 
                  product.vendor_longitude
                )}
              </p>
            )}
            <div className="flex items-center justify-between mt-2">
              <span className="text-xs font-semibold text-primary">
                {formatPrice(product.price_with_cylinder)}
              </span>
            </div>
          </Card>
        </motion.div>
      ))}
    </div>
  )}
</section>


      {/* Recent Vendors Section */}
      <section className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Trusted Vendors</h2>
          <Button 
            variant="link" 
            className="text-secondary p-0 h-auto font-semibold"
            onClick={() => navigate("/vendors")}
          >
            View All
          </Button>
        </div>

        {recentVendors.length === 0 ? (
          <Card className="p-6 text-center">
            <div className="text-4xl mb-3">🏪</div>
            <p className="text-muted-foreground">No vendors available yet</p>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {recentVendors.map((vendor, index) => (
              <motion.div
                key={vendor.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card 
                  className="p-4 cursor-pointer hover:shadow-lg transition-all duration-300"
                  onClick={() => handleVendorClick(vendor)}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 bg-gradient-to-br from-blue-100 to-blue-50 rounded-lg flex items-center justify-center">
                      <span className="text-xl">🏪</span>
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-sm">{vendor.business_name}</h3>
                      <p className="text-xs text-muted-foreground truncate">{vendor.address}</p>
                      <div className="flex items-center justify-between mt-2">
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-yellow-500">⭐</span>
                          <span className="text-xs font-medium">{vendor.average_rating}</span>
                          <span className="text-xs text-muted-foreground">
                            ({vendor.total_reviews})
                          </span>
                        </div>
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded-full">
                          Verified
                        </span>
                      </div>
                    </div>
                  </div>
                </Card>
              </motion.div>
            ))}
          </div>
        )}
      </section>

      {/* Quick Stats for Vendors/Mechanics */}
      {(currentUser?.user_type === 'vendor' || currentUser?.user_type === 'mechanic') && (
        <section className="p-4">
          <Card className="p-4 bg-gradient-to-r from-primary to-primary/90 text-white">
            <h3 className="font-semibold mb-2">Your Business Dashboard</h3>
            <p className="text-sm opacity-90 mb-3">
              Manage your services and track orders
            </p>
            <Button 
              variant="secondary" 
              size="sm"
              onClick={() => navigate("/vendor/dashboard")}
            >
              Go to Dashboard
            </Button>
          </Card>
        </section>
      )}

      {/* Bottom Navigation */}
      <BottomNav />
    </div>
  );
};

export default Dashboard;