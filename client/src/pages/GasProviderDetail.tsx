import { useState, useEffect } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { ArrowLeft, MapPin, Star, Phone, ShoppingCart, Loader2, Clock, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import GasProductCard from "@/components/GasProductCard";
import BottomNav from "@/components/BottomNav";
import { gasProductsAPI, vendorsAPI } from "@/services/api";
import { useCart } from "@/context/CartContext"; // ✅ Add CartContext import
import { toast } from "sonner";

// Updated interfaces to match your Django API
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

interface Vendor {
  id: number;
  business_name: string;
  business_type: string;
  description: string;
  address: string;
  city: string;
  country: string;
  contact_number: string;
  email: string;
  website: string;
  average_rating: number;
  total_reviews: number;
  is_verified: boolean;
  is_active: boolean;
  operating_hours: Array<{
    id: number;
    day: number;
    opening_time: string;
    closing_time: string;
    is_closed: boolean;
  }>;
  reviews: Array<{
    id: number;
    customer_name: string;
    rating: number;
    comment: string;
    created_at: string;
  }>;
  latitude?: number;
  longitude?: number;
}

const GasProviderDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { cartItemCount, cartTotal } = useCart(); // ✅ Use CartContext
  const [vendor, setVendor] = useState<Vendor | null>(null);
  const [gasProducts, setGasProducts] = useState<GasProduct[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("products");

  useEffect(() => {
    const fetchProviderData = async () => {
      try {
        setLoading(true);

        // If vendor data was passed via navigation state, use it
        if (location.state?.vendor) {
          setVendor(location.state.vendor);
          await fetchVendorProducts(location.state.vendor.id);
        } else {
          // Otherwise fetch vendor by ID
          await fetchVendorData();
        }
      } catch (error: any) {
        console.error("Error fetching provider data:", error);
        toast.error("Failed to load provider details");
        
        // Fallback to mock data
        setVendor(getMockVendorData());
        setGasProducts(getMockGasProducts());
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchProviderData();
    }
  }, [id, location.state]);

  const fetchVendorData = async () => {
    try {
      const response = await vendorsAPI.getVendor(Number(id));
      setVendor(response.data);
      await fetchVendorProducts(Number(id));
    } catch (error: any) {
      console.error("Error fetching vendor:", error);
      throw error;
    }
  };

  const fetchVendorProducts = async (vendorId: number) => {
    try {
      const response = await gasProductsAPI.getGasProducts({ 
        vendor: vendorId,
        is_available: true 
      });
      setGasProducts(response.data);
    } catch (error: any) {
      console.error("Error fetching vendor products:", error);
      // Fallback to mock products
      setGasProducts(getMockGasProducts());
    }
  };

  // Mock data fallbacks
  const getMockVendorData = (): Vendor => ({
    id: Number(id) || 1,
    business_name: "Nairobi Gas Center",
    business_type: "gas_station",
    description: "Your trusted partner for quality gas products and reliable service. We provide safe and efficient gas solutions for homes and businesses.",
    address: "Moi Avenue, Nairobi CBD",
    city: "Nairobi",
    country: "Kenya",
    contact_number: "+254712345678",
    email: "info@nairobigas.com",
    website: "https://nairobigas.com",
    average_rating: 4.5,
    total_reviews: 124,
    is_verified: true,
    is_active: true,
    latitude: -1.286389,
    longitude: 36.817223,
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
        rating: 5,
        comment: "Excellent service and fast delivery! The gas quality is top-notch.",
        created_at: "2024-01-15T10:30:00Z"
      },
      {
        id: 2,
        customer_name: "Mary Wanjiku",
        rating: 4,
        comment: "Good prices and reliable service. Will definitely order again.",
        created_at: "2024-01-10T14:20:00Z"
      },
      {
        id: 3,
        customer_name: "Peter Omondi",
        rating: 5,
        comment: "Very professional and timely delivery. Highly recommended!",
        created_at: "2024-01-08T09:15:00Z"
      }
    ]
  });

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
      description: "Premium quality LPG gas for home and commercial use",
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
      vendor_name: "Nairobi Gas Center",
      vendor_city: "Nairobi",
      vendor_latitude: -1.286389,
      vendor_longitude: 36.817223,
      is_available: true,
      in_stock: true,
      stock_quantity: 30,
      description: "Reliable household gas with safety features",
      vendor_address: "Moi Avenue, Nairobi CBD",
      vendor_contact: "+254712345678"
    },
    {
      id: 3,
      name: "Safe Gas LPG",
      gas_type: "lpg",
      cylinder_size: "22kg",
      price_with_cylinder: 5200,
      price_without_cylinder: 4500,
      vendor_name: "Nairobi Gas Center",
      vendor_city: "Nairobi",
      vendor_latitude: -1.286389,
      vendor_longitude: 36.817223,
      is_available: true,
      in_stock: true,
      stock_quantity: 20,
      description: "Commercial grade LPG for businesses and industries",
      vendor_address: "Moi Avenue, Nairobi CBD",
      vendor_contact: "+254712345678"
    }
  ];

  // Convert GasProduct to the format expected by GasProductCard
  const formatProductForCard = (product: GasProduct) => ({
    id: product.id,
    name: product.name,
    weight: product.cylinder_size,
    description: product.description || `${product.gas_type} gas cylinder`,
    priceWithCylinder: product.price_with_cylinder,
    priceWithoutCylinder: product.price_without_cylinder
  });

  const handleOrderNow = (product: any, includeCylinder: boolean) => {
    if (!vendor) return;

    const price = includeCylinder ? product.priceWithCylinder : product.priceWithoutCylinder;
    
    navigate('/checkout', {
      state: {
        orderItems: [{
          productId: product.id,
          vendorId: vendor.id,
          productName: product.name,
          vendorName: vendor.business_name,
          quantity: 1,
          unitPrice: price,
          totalAmount: price,
          includeCylinder,
          description: product.description
        }],
        totalAmount: price
      }
    });
  };

  const handleCheckout = () => {
    navigate('/checkout');
  };

  const formatOperatingHours = (hours: any[]) => {
    const today = new Date().getDay();
    const todayHours = hours.find(h => h.day === today);
    
    if (!todayHours || todayHours.is_closed) {
      return "Closed today";
    }
    
    return `Open today: ${todayHours.opening_time} - ${todayHours.closing_time}`;
  };

  const getDayDisplay = (day: number): string => {
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    return days[day] || 'Unknown';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Loading provider details...</p>
        </div>
      </div>
    );
  }

  if (!vendor) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4">🔥</div>
          <h3 className="text-lg font-semibold mb-2">Provider not found</h3>
          <p className="text-muted-foreground mb-4">The gas provider you're looking for doesn't exist.</p>
          <Button onClick={() => navigate('/services/gas')}>
            Back to Gas Services
          </Button>
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
              onClick={() => navigate("/services/gas")}
              className="text-white hover:bg-white/20"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div className="max-w-[200px]">
              <h1 className="text-xl font-semibold truncate">{vendor.business_name}</h1>
              <div className="flex items-center text-xs text-white/80">
                <MapPin className="h-3 w-3 mr-1 flex-shrink-0" />
                <span className="truncate">{vendor.address}</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Provider Info */}
      <div className="bg-card border-b p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Star className="h-5 w-5 fill-yellow-500 text-yellow-500" />
            <span className="font-semibold">{vendor.average_rating}</span>
            <span className="text-sm text-muted-foreground">
              ({vendor.total_reviews} reviews)
            </span>
          </div>
          <div className="flex items-center gap-2">
            {vendor.is_verified && (
              <Badge variant="secondary" className="bg-green-100 text-green-800">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                Verified
              </Badge>
            )}
            {!vendor.is_active && (
              <Badge variant="secondary" className="bg-red-100 text-red-800">
                Inactive
              </Badge>
            )}
          </div>
        </div>
        
        <div className="flex items-center gap-2 text-sm mb-2">
          <Phone className="h-4 w-4" />
          <span>{vendor.contact_number}</span>
        </div>

        {vendor.operating_hours && vendor.operating_hours.length > 0 && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="h-4 w-4" />
            <span>{formatOperatingHours(vendor.operating_hours)}</span>
          </div>
        )}
      </div>

      {/* Tabs for different sections */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 sticky top-[136px] z-30 rounded-none bg-background">
          <TabsTrigger value="products">Products</TabsTrigger>
          <TabsTrigger value="about">About</TabsTrigger>
          <TabsTrigger value="reviews">Reviews</TabsTrigger>
        </TabsList>

        <TabsContent value="products" className="m-0 p-4">
          <h2 className="text-xl font-semibold mb-4">Available Gas Products</h2>
          {gasProducts.length === 0 ? (
            <Card className="p-8 text-center">
              <div className="text-6xl mb-4">🔥</div>
              <h3 className="text-lg font-semibold mb-2">No products available</h3>
              <p className="text-muted-foreground">
                This provider doesn't have any gas products listed yet.
              </p>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {gasProducts.map(product => (
                <GasProductCard
                  key={product.id}
                  product={formatProductForCard(product)}
                  onOrderNow={handleOrderNow}
                  available={product.is_available && product.in_stock}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="about" className="m-0 p-4">
          <Card>
            <CardHeader>
              <CardTitle>About {vendor.business_name}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-semibold mb-2">Description</h4>
                <p className="text-muted-foreground">
                  {vendor.description}
                </p>
              </div>
              
              <div>
                <h4 className="font-semibold mb-2">Contact Information</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Phone:</span>
                    <span>{vendor.contact_number}</span>
                  </div>
                  {vendor.email && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Email:</span>
                      <span>{vendor.email}</span>
                    </div>
                  )}
                  {vendor.website && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Website:</span>
                      <span>{vendor.website}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Address:</span>
                    <span className="text-right">{vendor.address}, {vendor.city}, {vendor.country}</span>
                  </div>
                </div>
              </div>

              {vendor.operating_hours && vendor.operating_hours.length > 0 && (
                <div>
                  <h4 className="font-semibold mb-2">Operating Hours</h4>
                  <div className="space-y-1 text-sm">
                    {vendor.operating_hours.map(hour => (
                      <div key={hour.id} className="flex justify-between">
                        <span className="text-muted-foreground">{getDayDisplay(hour.day)}:</span>
                        <span>
                          {hour.is_closed ? 'Closed' : `${hour.opening_time} - ${hour.closing_time}`}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reviews" className="m-0 p-4">
          <Card>
            <CardHeader>
              <CardTitle>Customer Reviews</CardTitle>
            </CardHeader>
            <CardContent>
              {vendor.reviews && vendor.reviews.length > 0 ? (
                <div className="space-y-4">
                  {vendor.reviews.map(review => (
                    <div key={review.id} className="border-b pb-4 last:border-b-0">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="flex items-center gap-1">
                          {[...Array(5)].map((_, i) => (
                            <Star
                              key={i}
                              className={`h-4 w-4 ${
                                i < review.rating
                                  ? 'fill-yellow-500 text-yellow-500'
                                  : 'text-gray-300'
                              }`}
                            />
                          ))}
                        </div>
                        <span className="font-semibold">{review.customer_name}</span>
                      </div>
                      {review.comment && (
                        <p className="text-sm text-muted-foreground mb-2">{review.comment}</p>
                      )}
                      <p className="text-xs text-muted-foreground">
                        {new Date(review.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Star className="h-12 w-12 text-gray-300 mx-auto mb-4" />
                  <p className="text-muted-foreground">No reviews yet</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Be the first to review this provider!
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Floating Cart Button */}
      {cartItemCount > 0 && (
        <div className="fixed bottom-20 right-4 z-30">
          <Button
            size="lg"
            className="rounded-full shadow-lg h-14 px-6 bg-secondary hover:bg-secondary/90"
            onClick={handleCheckout}
          >
            <ShoppingCart className="h-5 w-5 mr-2" />
            <span className="font-semibold">{cartItemCount}</span>
            <span className="mx-2">•</span>
            <span>KSh {cartTotal.toLocaleString()}</span>
          </Button>
        </div>
      )}

      <BottomNav />
    </div>
  );
};

export default GasProviderDetail;