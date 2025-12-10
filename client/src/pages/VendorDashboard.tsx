// src/pages/VendorDashboard.tsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Plus, Package, Star, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import BottomNav from "@/components/BottomNav";
import { vendorsAPI, gasProductsAPI } from "@/services/api";

const VendorDashboard = () => {
  const navigate = useNavigate();
  const [vendor, setVendor] = useState<any>(null);
  const [products, setProducts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchVendorData = async () => {
      try {
        const [vendorRes, productsRes] = await Promise.all([
          vendorsAPI.getMyVendor(),
          gasProductsAPI.getMyProducts()
        ]);
        setVendor(vendorRes.data);
        setProducts(productsRes.data);
      } catch (error) {
        console.error("Error fetching vendor data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchVendorData();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
        <div className="flex items-center gap-3 p-4">
          <Button 
            variant="ghost" 
            size="icon" 
            onClick={() => navigate("/dashboard")}
            className="text-white hover:bg-white/20"
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-semibold">Vendor Dashboard</h1>
        </div>
      </header>

      <div className="p-4 space-y-4">
        {/* Stats Overview */}
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4 text-center">
            <Package className="h-8 w-8 mx-auto mb-2 text-primary" />
            <p className="text-2xl font-bold">{products.length}</p>
            <p className="text-sm text-muted-foreground">Products</p>
          </Card>
          
          <Card className="p-4 text-center">
            <Star className="h-8 w-8 mx-auto mb-2 text-yellow-500" />
            <p className="text-2xl font-bold">{vendor?.average_rating || 0}</p>
            <p className="text-sm text-muted-foreground">Rating</p>
          </Card>
        </div>

        {/* Quick Actions */}
        <Card className="p-4">
          <h3 className="font-semibold mb-3">Quick Actions</h3>
          <div className="space-y-2">
            <Button className="w-full justify-start" variant="outline">
              <Plus className="h-4 w-4 mr-2" />
              Add New Product
            </Button>
            <Button className="w-full justify-start" variant="outline">
              <Users className="h-4 w-4 mr-2" />
              View Orders
            </Button>
          </div>
        </Card>

        {/* Recent Products */}
        <Card className="p-4">
          <h3 className="font-semibold mb-3">Your Products</h3>
          {products.length === 0 ? (
            <p className="text-muted-foreground text-center py-4">No products yet</p>
          ) : (
            <div className="space-y-2">
              {products.slice(0, 3).map((product) => (
                <div key={product.id} className="flex justify-between items-center p-2 border rounded">
                  <div>
                    <p className="font-medium">{product.name}</p>
                    <p className="text-sm text-muted-foreground">{product.cylinder_size}</p>
                  </div>
                  <p className="font-semibold">KSh {product.price_with_cylinder.toLocaleString()}</p>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <BottomNav />
    </div>
  );
};

export default VendorDashboard;