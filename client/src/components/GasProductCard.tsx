// src/components/GasProductCard.tsx - Updated version
import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Plus, Minus, ShoppingCart, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { useCart } from "@/context/CartContext";

interface GasProduct {
  id: number;
  name: string;
  weight: string;
  description: string;
  priceWithCylinder: number;
  priceWithoutCylinder: number;
}

interface GasProductCardProps {
  product: GasProduct;
  onOrderNow?: (product: GasProduct, includeCylinder: boolean) => void;
  available: boolean;
}


const GasProductCard = ({ product, onOrderNow, available }: GasProductCardProps) => {
  const [quantity, setQuantity] = useState(1);
  const [includeCylinder, setIncludeCylinder] = useState(false);
  const [addingToCart, setAddingToCart] = useState(false);
  
  const { addToCart, refreshCart } = useCart();

  const currentPrice = includeCylinder ? product.priceWithCylinder : product.priceWithoutCylinder;
  const totalPrice = currentPrice * quantity;

  const handleAddToCart = async () => {
    if (!available) {
      toast.error("This product is currently unavailable");
      return;
    }

    setAddingToCart(true);
    try {
      console.log('🛒 Adding product to cart:', { productId: product.id, quantity });
      
      // ✅ Add timeout handling
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Request timeout')), 8000)
      );
      
      // ✅ Use Promise.race to handle timeout
      await Promise.race([addToCart(product.id, quantity), timeoutPromise]);
      toast.success(`Added ${quantity}x ${product.name} to cart`);
      
      // Refresh cart to ensure UI updates
      await refreshCart();
      
    } catch (error: any) {
      console.error('❌ Error adding to cart:', error);
      
      if (error.message === 'Please log in to add items to cart') {
        toast.error("Please log in to add items to cart");
      } else if (error.message === 'Request timeout') {
        toast.error("Request took too long. Please check your connection.");
      } else {
        toast.error("Failed to add to cart. Please try again.");
      }
    } finally {
      setAddingToCart(false);
    }
  };

  const handleOrderNow = () => {
    if (onOrderNow) {
      onOrderNow(product, includeCylinder);
    }
  };

  return (
    <Card className="p-4 hover:shadow-lg transition-shadow">
      <div className="space-y-4">
        <div>
          <h3 className="font-semibold text-lg">{product.name}</h3>
          <p className="text-sm text-muted-foreground">{product.weight}</p>
          <p className="text-sm text-muted-foreground mt-1">{product.description}</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-2">
              <input
                type="radio"
                id={`without-${product.id}`}
                name={`cylinder-${product.id}`}
                checked={!includeCylinder}
                onChange={() => setIncludeCylinder(false)}
                className="cursor-pointer"
              />
              <label htmlFor={`without-${product.id}`} className="cursor-pointer text-sm">
                Without Cylinder
              </label>
            </div>
            <span className="font-semibold">KSh {product.priceWithoutCylinder.toLocaleString()}</span>
          </div>

          <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-2">
              <input
                type="radio"
                id={`with-${product.id}`}
                name={`cylinder-${product.id}`}
                checked={includeCylinder}
                onChange={() => setIncludeCylinder(true)}
                className="cursor-pointer"
              />
              <label htmlFor={`with-${product.id}`} className="cursor-pointer text-sm">
                With Cylinder
              </label>
            </div>
            <span className="font-semibold">KSh {product.priceWithCylinder.toLocaleString()}</span>
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => setQuantity(Math.max(1, quantity - 1))}
              className="h-8 w-8"
              disabled={!available}
            >
              <Minus className="h-4 w-4" />
            </Button>
            <span className="font-semibold w-8 text-center">{quantity}</span>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setQuantity(quantity + 1)}
              className="h-8 w-8"
              disabled={!available}
            >
              <Plus className="h-4 w-4" />
            </Button>
          </div>

          <div className="text-right">
            <p className="text-xs text-muted-foreground">Total</p>
            <p className="text-xl font-bold text-primary">KSh {totalPrice.toLocaleString()}</p>
          </div>
        </div>

        <div className="flex gap-2">
          <Button 
            onClick={handleAddToCart} 
            className="flex-1" 
            size="lg"
            disabled={!available || addingToCart}
          >
            {addingToCart ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <ShoppingCart className="h-4 w-4 mr-2" />
            )}
            {addingToCart ? "Adding..." : "Add to Cart"}
          </Button>
          
          {onOrderNow && (
            <Button 
              onClick={handleOrderNow}
              variant="outline"
              size="lg"
              disabled={!available}
            >
              Order Now
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
};

export default GasProductCard;