import { useState, useEffect } from "react"; 
import { useNavigate } from "react-router-dom";
import { ArrowLeft, MapPin, Filter, Search, Star, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Map from "@/components/Map";
import BottomNav from "@/components/BottomNav";
import { motion } from "framer-motion";
import { gasProductsAPI, vendorsAPI } from "@/services/api";
import { toast } from "sonner";

// Updated interface for Gas Products
interface GasProduct {
  id: number;
  name: string;
  gas_type: string;
  cylinder_size: string;
  price_with_cylinder: number;
  price_without_cylinder: number;
  vendor_name: string;
  vendor_city: string;
  vendor_latitude: number;
  vendor_longitude: number;
  is_available: boolean;
  in_stock: boolean;
  stock_quantity: number;
  description?: string;
  vendor_address: string;
  vendor_contact: string;
}

const GasServices = () => {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState("map");
  const [products, setProducts] = useState<GasProduct[]>([]);
  const [loading, setLoading] = useState(true);
  const [userLocation, setUserLocation] = useState<[number, number] | null>(null);

  // Get user's current location
  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setUserLocation([latitude, longitude]);
          fetchGasProducts(latitude, longitude);
        },
        (error) => {
          console.error("Error getting location:", error);
          fetchGasProducts(); // Fetch without location
        }
      );
    } else {
      fetchGasProducts(); // Fetch without location
    }
  }, []);

  const fetchGasProducts = async (lat?: number, lng?: number) => {
    try {
      setLoading(true);
      const filters: any = {
        is_available: true,
        vendor__is_verified: true
      };

      // Add location filters if available
      if (lat && lng) {
        filters.lat = lat;
        filters.lng = lng;
        filters.radius = 20; // 20km radius
      }

      const response = await gasProductsAPI.getGasProducts(filters);
      setProducts(response.data);
    } catch (error: any) {
      console.error("Error fetching gas products:", error);
      toast.error("Failed to load gas products");
      
      // Fallback to mock data if API fails
      setProducts(getMockGasProducts());
    } finally {
      setLoading(false);
    }
  };

  // Mock data fallback
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
      description: "Premium quality LPG gas",
      vendor_address: "Moi Avenue, Nairobi CBD",
      vendor_contact: "+254712345678"
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
      description: "Reliable household gas",
      vendor_address: "Westlands Mall, Nairobi",
      vendor_contact: "+254723456789"
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
      description: "Commercial grade LPG",
      vendor_address: "Argwings Kodhek Road, Kilimani",
      vendor_contact: "+254734567890"
    }
  ];

  const filteredProducts = products.filter(product =>
    product.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    product.vendor_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    product.vendor_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
    product.cylinder_size.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const calculateDistance = (lat1: number, lon1: number, lat2: number, lon2: number): string => {
    if (!lat1 || !lon1 || !lat2 || !lon2) return "Unknown";
    
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
  };

  const formatPrice = (price: number) => {
    return `KSh ${price.toLocaleString()}`;
  };

  // Updated click handler - FIXED: Use consistent route pattern
  const handleProductClick = (product: GasProduct) => {
    navigate(`/services/gas/providers/${product.id}`, {
      state: {
        product: product,
        vendor: {
          id: product.id,
          business_name: product.vendor_name,
          address: product.vendor_address,
          contact_number: product.vendor_contact,
          city: product.vendor_city,
          latitude: product.vendor_latitude,
          longitude: product.vendor_longitude,
          business_type: 'gas_station' // Add business_type for consistency
        }
      }
    });
  };

  const handleRefresh = () => {
    if (userLocation) {
      fetchGasProducts(userLocation[0], userLocation[1]);
    } else {
      fetchGasProducts();
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Loading gas products...</p>
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
              <h1 className="text-xl font-semibold">Gas Services</h1>
              <div className="flex items-center text-xs text-white/80">
                <MapPin className="h-3 w-3 mr-1" />
                <span>
                  {userLocation ? "Near you" : "Gas products nearby"}
                </span>
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={handleRefresh}
              className="text-white hover:bg-white/20"
              disabled={loading}
            >
              <Loader2 className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
            </Button>
            <Button variant="ghost" size="icon" className="text-white hover:bg-white/20">
              <Filter className="h-5 w-5" />
            </Button>
          </div>
        </div>
        
        {/* Search Bar */}
        <div className="px-4 pb-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              type="search"
              placeholder="Search gas products, vendors, or locations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-white text-foreground"
            />
          </div>
        </div>
      </header>

      {/* Tabs for Map/List View */}
      <Tabs value={viewMode} onValueChange={setViewMode} className="w-full">
        <TabsList className="grid w-full grid-cols-2 sticky top-[136px] z-30 rounded-none bg-background">
          <TabsTrigger value="map">Map View</TabsTrigger>
          <TabsTrigger value="list">List View</TabsTrigger>
        </TabsList>

        <TabsContent value="map" className="m-0">
          <div className="h-[400px] relative">
            <Map 
              providers={filteredProducts.map(product => ({
                id: product.id,
                name: product.vendor_name,
                location: product.vendor_address,
                price: formatPrice(product.price_with_cylinder),
                rating: 4.5,
                distance: userLocation 
                  ? calculateDistance(
                      userLocation[0], 
                      userLocation[1], 
                      product.vendor_latitude, 
                      product.vendor_longitude
                    )
                  : "Unknown",
                coords: [product.vendor_latitude, product.vendor_longitude] as [number, number]
              }))}
              userLocation={userLocation}
            />
          </div>
          
          {/* Product cards below map */}
          <div className="p-4 space-y-3">
            {filteredProducts.length === 0 ? (
              <Card className="p-8 text-center">
                <div className="text-6xl mb-4">🔥</div>
                <h3 className="text-lg font-semibold mb-2">No gas products found</h3>
                <p className="text-muted-foreground">
                  {searchQuery ? "Try adjusting your search terms" : "No gas products available in your area"}
                </p>
              </Card>
            ) : (
              filteredProducts.map((product, index) => (
                <motion.div
                  key={product.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                >
                  <Card 
                    className="p-4 cursor-pointer hover:shadow-lg transition-all duration-300 border-2 border-transparent hover:border-primary/20"
                    onClick={() => handleProductClick(product)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <h3 className="font-semibold text-lg">{product.vendor_name}</h3>
                          {!product.is_available && (
                            <span className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded-full">
                              Out of Stock
                            </span>
                          )}
                          {product.in_stock && product.stock_quantity < 10 && (
                            <span className="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded-full">
                              Low Stock
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">
                          {product.name} - {product.cylinder_size}
                        </p>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <MapPin className="h-4 w-4" />
                          <span className="flex-1">{product.vendor_address}</span>
                        </div>
                        <div className="flex items-center justify-between mt-2">
                          <div className="text-lg font-bold text-primary">
                            {formatPrice(product.price_with_cylinder)}
                          </div>
                          {userLocation && (
                            <div className="text-sm text-muted-foreground">
                              {calculateDistance(
                                userLocation[0], 
                                userLocation[1], 
                                product.vendor_latitude, 
                                product.vendor_longitude
                              )} away
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          <div className="flex items-center gap-1">
                            <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                            <span className="text-sm">4.5</span>
                          </div>
                          <span className="text-sm text-muted-foreground">
                            • {product.vendor_contact}
                          </span>
                          <span className="text-sm text-muted-foreground">
                            • Stock: {product.stock_quantity}
                          </span>
                        </div>
                      </div>
                      <div className="text-4xl ml-4">🔥</div>
                    </div>
                  </Card>
                </motion.div>
              ))
            )}
          </div>
        </TabsContent>

        <TabsContent value="list" className="m-0 p-4">
          <div className="space-y-3">
            {filteredProducts.length === 0 ? (
              <Card className="p-8 text-center">
                <div className="text-6xl mb-4">🔥</div>
                <h3 className="text-lg font-semibold mb-2">No gas products found</h3>
                <p className="text-muted-foreground">
                  {searchQuery ? "Try adjusting your search terms" : "No gas products available in your area"}
                </p>
              </Card>
            ) : (
              filteredProducts.map((product, index) => (
                <motion.div
                  key={product.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <Card 
                    className="p-4 cursor-pointer hover:shadow-lg transition-all duration-300 border-2 border-transparent hover:border-primary/20"
                    onClick={() => handleProductClick(product)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <h3 className="font-semibold text-lg">{product.vendor_name}</h3>
                          {!product.is_available && (
                            <span className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded-full">
                              Out of Stock
                            </span>
                          )}
                          {product.in_stock && product.stock_quantity < 10 && (
                            <span className="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded-full">
                              Low Stock
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">
                          {product.name} - {product.cylinder_size}
                        </p>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <MapPin className="h-4 w-4" />
                          <span>{product.vendor_address}</span>
                        </div>
                        <div className="flex items-center justify-between mt-3">
                          <div className="text-lg font-bold text-primary">
                            {formatPrice(product.price_with_cylinder)}
                          </div>
                          {userLocation && (
                            <div className="text-sm text-muted-foreground">
                              {calculateDistance(
                                userLocation[0], 
                                userLocation[1], 
                                product.vendor_latitude, 
                                product.vendor_longitude
                              )} away
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          <div className="flex items-center gap-1">
                            <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                            <span className="text-sm">4.5</span>
                          </div>
                          <span className="text-sm text-muted-foreground">
                            • {product.vendor_contact}
                          </span>
                          <span className="text-sm text-muted-foreground">
                            • Stock: {product.stock_quantity}
                          </span>
                        </div>
                        <Button 
                          className="mt-3 bg-secondary hover:bg-secondary/90 text-white w-full"
                          size="sm"
                          disabled={!product.is_available}
                          onClick={() => handleProductClick(product)}
                        >
                          {product.is_available ? "View Details & Order" : "Out of Stock"}
                        </Button>
                      </div>
                      <div className="text-5xl ml-4">🔥</div>
                    </div>
                  </Card>
                </motion.div>
              ))
            )}
          </div>
        </TabsContent>
      </Tabs>

      <BottomNav />
    </div>
  );
};

export default GasServices;