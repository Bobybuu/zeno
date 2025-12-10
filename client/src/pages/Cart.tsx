// src/pages/Cart.tsx - Updated version
import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Trash2, Plus, Minus, ShoppingBag, Loader2, MapPin, Phone, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import BottomNav from "@/components/BottomNav";
import { motion } from "framer-motion";
import { useCart } from "@/context/CartContext";

// Updated interfaces to match your Django backend
interface GasProduct {
  id: number;
  name: string;
  gas_type: string;
  cylinder_size: string;
  brand: string;
  price_with_cylinder: number;
  price_without_cylinder: number;
  vendor_name: string;
  vendor_city: string;
  vendor_address: string;
  vendor_contact: string;
  is_available: boolean;
  in_stock: boolean;
  stock_quantity: number;
  min_stock_alert: number;
  description?: string;
}

interface CartItem {
  id: number;
  item_type: string;
  gas_product?: number;
  product?: number;
  product_id?: number;
  quantity: number;
  unit_price: string | number;
  total_price: string | number;
  added_at: string;
  item_name: string;
  include_cylinder?: boolean;
  gas_product_details?: any;
}

const Cart = () => {
  const navigate = useNavigate();
  const [isProcessing, setIsProcessing] = useState(false);
  
  // ✅ Use CartContext
  const { 
    cart, 
    loading, 
    refreshCart, 
    updateCartItem, 
    removeFromCart, 
    clearCart 
  } = useCart();

  // Debug logging
  useEffect(() => {
    console.log('🔍 CART DEBUG - Full cart object:', cart);
    console.log('🔍 CART DEBUG - Cart items:', cart?.items);
    console.log('🔍 CART DEBUG - Loading state:', loading);
  }, [cart, loading]);

  // Refresh cart on component mount
  useEffect(() => {
    let isMounted = true;
    
    const loadCart = async () => {
      if (isMounted) {
        console.log('🔄 Loading cart on component mount');
        await refreshCart();
      }
    };
    
    loadCart();
    
    return () => {
      isMounted = false;
    };
  }, []);

  // Create mock gas product data for display (fallback)
  const createMockGasProduct = (productId: number): GasProduct => {
    const mockProducts: { [key: number]: GasProduct } = {
      1: {
        id: 1,
        name: "Pro Gas LPG",
        gas_type: "lpg",
        cylinder_size: "13kg",
        brand: "Pro Gas",
        price_with_cylinder: 3500,
        price_without_cylinder: 2800,
        vendor_name: "Nairobi Gas Center",
        vendor_city: "Nairobi",
        vendor_address: "Moi Avenue, Nairobi CBD",
        vendor_contact: "+254712345678",
        is_available: true,
        in_stock: true,
        stock_quantity: 50,
        min_stock_alert: 5,
        description: "Premium quality LPG gas"
      },
      2: {
        id: 2,
        name: "K-Gas LPG",
        gas_type: "lpg",
        cylinder_size: "6kg",
        brand: "K-Gas",
        price_with_cylinder: 1800,
        price_without_cylinder: 1500,
        vendor_name: "Westlands Gas Shop",
        vendor_city: "Nairobi",
        vendor_address: "Westlands Mall, Nairobi",
        vendor_contact: "+254723456789",
        is_available: true,
        in_stock: true,
        stock_quantity: 30,
        min_stock_alert: 3,
        description: "Reliable household gas"
      },
      3: {
        id: 3,
        name: "Safe Gas LPG",
        gas_type: "lpg",
        cylinder_size: "22kg",
        brand: "Safe Gas",
        price_with_cylinder: 5200,
        price_without_cylinder: 4500,
        vendor_name: "Kilimani Gas Depot",
        vendor_city: "Nairobi",
        vendor_address: "Argwings Kodhek Road, Kilimani",
        vendor_contact: "+254734567890",
        is_available: true,
        in_stock: true,
        stock_quantity: 20,
        min_stock_alert: 2,
        description: "Commercial grade LPG"
      }
    };

    return mockProducts[productId] || {
      id: productId,
      name: "Gas Product",
      gas_type: "lpg",
      cylinder_size: "13kg",
      brand: "Generic",
      price_with_cylinder: 3000,
      price_without_cylinder: 2500,
      vendor_name: "Gas Vendor",
      vendor_city: "Nairobi",
      vendor_address: "Unknown Address",
      vendor_contact: "+254700000000",
      is_available: true,
      in_stock: true,
      stock_quantity: 10,
      min_stock_alert: 2,
      description: "Gas cylinder"
    };
  };

  // ✅ FIXED: Filter only gas products for display with better detection
  const gasProductItems: CartItem[] = useMemo(() => {
    if (!cart?.items || !Array.isArray(cart.items)) {
      console.log('🔄 No cart items or items is not an array');
      return [];
    }
    
    console.log('🔍 All cart items:', cart.items);
    
    const filteredItems = cart.items.filter((item: CartItem) => {
      // Check multiple possible indicators of a gas product from backend
      const isGasProduct = 
        item.item_type === 'gas_product' || 
        item.gas_product !== undefined ||
        item.product_id !== undefined ||
        item.product !== undefined ||
        (item.item_name && item.item_name.toLowerCase().includes('gas'));
      
      console.log(`🔄 Filtering item ${item.id}:`, { 
        item_type: item.item_type,
        gas_product: item.gas_product,
        product_id: item.product_id,
        product: item.product,
        item_name: item.item_name,
        isGasProduct 
      });
      
      return isGasProduct;
    });
    
    console.log('✅ Filtered gas product items:', filteredItems);
    console.log('📊 Total cart items:', cart.items.length);
    console.log('📊 Filtered gas items:', filteredItems.length);
    
    return filteredItems;
  }, [cart?.items]);

  // ✅ ADDED: Debug the actual item structures
  useEffect(() => {
    if (gasProductItems.length > 0) {
      console.log('🔍 DETAILED ITEM ANALYSIS:');
      gasProductItems.forEach((item: CartItem, index: number) => {
        console.log(`Item ${index} structure:`, {
          id: item.id,
          item_type: item.item_type,
          gas_product: item.gas_product,
          product_id: item.product_id,
          product: item.product,
          quantity: item.quantity,
          unit_price: item.unit_price,
          total_price: item.total_price,
          item_name: item.item_name,
          include_cylinder: item.include_cylinder,
          has_unit_price: item.unit_price !== undefined,
          has_total_price: item.total_price !== undefined,
        });
      });
    }
  }, [gasProductItems]);

  // Handle quantity update with error handling
  const handleUpdateQuantity = async (itemId: number, newQuantity: number) => {
    if (newQuantity < 1) return;
    
    setIsProcessing(true);
    try {
      await updateCartItem(itemId, newQuantity);
      toast.success("Cart updated");
    } catch (error: any) {
      console.error('Error updating quantity:', error);
      toast.error("Failed to update quantity");
      await refreshCart();
    } finally {
      setIsProcessing(false);
    }
  };

  // Handle item removal with error handling
  const handleRemoveItem = async (itemId: number) => {
    setIsProcessing(true);
    try {
      await removeFromCart(itemId);
      toast.success("Item removed from cart");
    } catch (error: any) {
      console.error('Error removing item:', error);
      toast.error("Failed to remove item");
      await refreshCart();
    } finally {
      setIsProcessing(false);
    }
  };

  // Handle clear cart with confirmation
  const handleClearCart = async () => {
    if (!gasProductItems.length) return;
    
    if (window.confirm("Are you sure you want to clear your cart?")) {
      setIsProcessing(true);
      try {
        await clearCart();
        toast.success("Cart cleared");
      } catch (error: any) {
        console.error('Error clearing cart:', error);
        toast.error("Failed to clear cart");
        await refreshCart();
      } finally {
        setIsProcessing(false);
      }
    }
  };

  // Calculate delivery fee
  const calculateDeliveryFee = (items: CartItem[]): number => {
    if (!items || items.length === 0) return 0;
    return 200; // Fixed delivery fee for demo
  };

  // Check if any gas product is unavailable
  const hasUnavailableItems = gasProductItems.some((item: CartItem) => {
    const productId = item.gas_product || item.product_id || item.product || item.id;
    const productDetails = item.gas_product_details || createMockGasProduct(productId);
    return !productDetails.is_available || !productDetails.in_stock;
  });

  // Check for low stock items
  const hasLowStockItems = gasProductItems.some((item: CartItem) => {
    const productId = item.gas_product || item.product_id || item.product || item.id;
    const productDetails = item.gas_product_details || createMockGasProduct(productId);
    return productDetails.in_stock && productDetails.stock_quantity < 3;
  });

  // Check for critical stock items (very low stock)
  const hasCriticalStockItems = gasProductItems.some((item: CartItem) => {
    const productId = item.gas_product || item.product_id || item.product || item.id;
    const productDetails = item.gas_product_details || createMockGasProduct(productId);
    return productDetails.in_stock && productDetails.stock_quantity === 1;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-24 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading cart...</p>
        </div>
      </div>
    );
  }

  const subtotal = parseFloat(cart?.total_amount?.toString() || '0') || 0;
  const deliveryFee = calculateDeliveryFee(gasProductItems);
  const total = subtotal + deliveryFee;

  console.log('🛒 Final cart data in component:', { 
    cart, 
    gasProductItems, 
    subtotal, 
    total,
    itemCount: gasProductItems.length 
  });

  return (
    <div className="min-h-screen bg-background pb-24">
      {/* Header */}
      <header className="sticky top-0 z-40 bg-primary text-white shadow-lg">
        <div className="flex items-center justify-between p-4">
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={() => navigate(-1)}
              className="text-white hover:bg-white/20"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <h1 className="text-xl font-semibold">Gas Cart</h1>
          </div>
          <div className="flex items-center gap-2">
            <ShoppingBag className="h-5 w-5" />
            <span className="text-sm">{gasProductItems.length} items</span>
          </div>
        </div>
      </header>

      <div className="p-4 space-y-4">
        {gasProductItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12">
            <div className="text-6xl mb-4">🔥</div>
            <h3 className="text-lg font-semibold mb-2">Your gas cart is empty</h3>
            <p className="text-muted-foreground text-center mb-6">
              Add gas products to your cart to get started
            </p>
            <Button onClick={() => navigate("/services/gas")}>
              Browse Gas Products
            </Button>
          </div>
        ) : (
          <>
            {/* Cart Header with Clear Button */}
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold">Gas Products ({gasProductItems.length})</h2>
              <Button
                variant="outline"
                size="sm"
                onClick={handleClearCart}
                disabled={isProcessing}
                className="text-destructive hover:text-destructive"
              >
                {isProcessing ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  "Clear All"
                )}
              </Button>
            </div>

            {/* Cart Items */}
            <div className="space-y-3">
              {gasProductItems.map((item: CartItem, index: number) => {
                // Get the actual product ID from any possible field
                const productId = item.gas_product || item.product_id || item.product || item.id;
                const productDetails = item.gas_product_details || createMockGasProduct(productId);
                
                // ✅ FIXED: Ensure prices are numbers with proper fallbacks
                const unitPrice = typeof item.unit_price === 'string' ? 
                  parseFloat(item.unit_price) : 
                  (item.unit_price || 0);
                
                const totalPrice = typeof item.total_price === 'string' ? 
                  parseFloat(item.total_price) : 
                  (item.total_price || 0);
                
                const isUnavailable = !productDetails.is_available || !productDetails.in_stock;
                const isLowStock = productDetails.in_stock && productDetails.stock_quantity < 5;
                const isCriticalStock = productDetails.in_stock && productDetails.stock_quantity === 1;
                
                console.log(`🔄 Rendering cart item ${item.id}:`, { 
                  productId, 
                  item,
                  productDetails,
                  unitPrice,
                  totalPrice
                });
                
                return (
                  <motion.div
                    key={item.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <Card className={`p-4 ${isUnavailable ? 'opacity-60' : ''}`}>
                      <div className="flex gap-4">
                        {/* Gas Product Icon */}
                        <div className="w-16 h-16 rounded-lg bg-orange-100 flex items-center justify-center">
                          <span className="text-2xl">🔥</span>
                        </div>
                        
                        {/* Product Details */}
                        <div className="flex-1">
                          <div className="flex items-start justify-between">
                            <h3 className="font-semibold">
                              {productDetails.name}
                            </h3>
                            {isCriticalStock && (
                              <Badge variant="destructive" className="text-xs">
                                <AlertTriangle className="h-3 w-3 mr-1" />
                                Last One
                              </Badge>
                            )}
                          </div>
                          
                          <p className="text-sm text-muted-foreground">
                            {productDetails.cylinder_size} • {productDetails.gas_type?.toUpperCase()}
                          </p>
                          
                          {/* Cylinder Option */}
                          {item.include_cylinder !== undefined && (
                            <Badge variant="outline" className="mt-1 text-xs">
                              {item.include_cylinder ? 'With Cylinder' : 'Without Cylinder'}
                            </Badge>
                          )}
                          
                          {/* Vendor Info */}
                          <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
                            <MapPin className="h-3 w-3" />
                            <span>{productDetails.vendor_name}</span>
                          </div>
                          
                          {/* Availability Badge */}
                          {isUnavailable && (
                            <Badge variant="destructive" className="mt-1 text-xs">
                              Currently Unavailable
                            </Badge>
                          )}
                          
                          {/* Stock Warning */}
                          {isLowStock && !isCriticalStock && (
                            <Badge variant="outline" className="mt-1 text-xs bg-orange-50 text-orange-700">
                              Low Stock: {productDetails.stock_quantity} left
                            </Badge>
                          )}
                          
                          <div className="flex items-center justify-between mt-2">
                            <span className="font-bold text-primary">
                              {/* ✅ FIXED: Safe total price display */}
                              KSh {totalPrice ? totalPrice.toLocaleString() : '0'}
                            </span>
                            
                            {/* Quantity Controls */}
                            <div className="flex items-center gap-2">
                              <Button
                                variant="outline"
                                size="icon"
                                className="h-7 w-7"
                                onClick={() => handleUpdateQuantity(item.id, item.quantity - 1)}
                                disabled={isProcessing || item.quantity <= 1}
                              >
                                <Minus className="h-3 w-3" />
                              </Button>
                              <span className="w-8 text-center font-medium">
                                {isProcessing ? (
                                  <Loader2 className="h-3 w-3 animate-spin mx-auto" />
                                ) : (
                                  item.quantity
                                )}
                              </span>
                              <Button
                                variant="outline"
                                size="icon"
                                className="h-7 w-7"
                                onClick={() => handleUpdateQuantity(item.id, item.quantity + 1)}
                                disabled={
                                  isProcessing ||
                                  isUnavailable ||
                                  item.quantity >= productDetails.stock_quantity
                                }
                              >
                                <Plus className="h-3 w-3" />
                              </Button>
                            </div>
                          </div>
                        </div>
                        
                        {/* Remove Button */}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive hover:bg-destructive/10"
                          onClick={() => handleRemoveItem(item.id)}
                          disabled={isProcessing}
                        >
                          {isProcessing ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                      
                      {/* Unit Price */}
                      <div className="mt-2 text-sm text-muted-foreground">
                        {/* ✅ FIXED: Safe unit price display */}
                        Unit price: KSh {unitPrice ? unitPrice.toLocaleString() : '0'} each
                      </div>
                    </Card>
                  </motion.div>
                );
              })}
            </div>

            {/* Order Summary */}
            <Card className="p-4 sticky bottom-20 shadow-lg">
              <h3 className="font-semibold mb-3">Order Summary</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Subtotal ({gasProductItems.length} items)</span>
                  <span>KSh {subtotal.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Delivery Fee</span>
                  <span>KSh {deliveryFee.toLocaleString()}</span>
                </div>
                <Separator className="my-2" />
                <div className="flex justify-between text-base font-bold">
                  <span>Total</span>
                  <span className="text-primary">KSh {total.toLocaleString()}</span>
                </div>
              </div>
              
              {/* Availability Warnings */}
              {hasUnavailableItems && (
                <div className="mt-3 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                  <p className="text-destructive text-sm">
                    ⚠️ Some items in your cart are currently unavailable. Please remove them to proceed.
                  </p>
                </div>
              )}
              
              {hasCriticalStockItems && (
                <div className="mt-3 p-3 bg-red-100 border border-red-200 rounded-lg">
                  <p className="text-red-800 text-sm">
                    🚨 Some items have very low stock. Order now to avoid missing out.
                  </p>
                </div>
              )}
              
              {hasLowStockItems && !hasCriticalStockItems && (
                <div className="mt-3 p-3 bg-orange-100 border border-orange-200 rounded-lg">
                  <p className="text-orange-800 text-sm">
                    📦 Some items have low stock. Order soon to avoid disappointment.
                  </p>
                </div>
              )}
              
              <Button 
                  className="w-full mt-4 bg-secondary hover:bg-secondary/90"
                  size="lg"
                  onClick={() => {
                    console.log('🛒 Navigating to checkout with items:', gasProductItems);
                    
                    // Transform cart items to match Checkout.tsx expected format
                    const orderItems = gasProductItems.map((item: CartItem) => {
                      const productId = item.gas_product || item.product_id || item.product || item.id;
                      const productDetails = item.gas_product_details || createMockGasProduct(productId);
                      
                      const unitPrice = typeof item.unit_price === 'string' ? 
                        parseFloat(item.unit_price) : 
                        (item.unit_price || 0);
                      
                      const totalPrice = typeof item.total_price === 'string' ? 
                        parseFloat(item.total_price) : 
                        (item.total_price || 0);

                      return {
                        id: item.id,
                        productId: productId,
                        productName: productDetails.name,
                        vendorName: productDetails.vendor_name,
                        quantity: item.quantity,
                        unitPrice: unitPrice,
                        totalAmount: totalPrice,
                        includeCylinder: item.include_cylinder || false,
                        description: `${productDetails.cylinder_size} • ${productDetails.gas_type?.toUpperCase()}`
                      };
                    });

                    console.log('🛒 Transformed order items:', orderItems);

                    navigate("/checkout", { 
                      state: { 
                        orderItems: orderItems, // ✅ Changed from cartItems to orderItems
                        totalAmount: total,
                        cartData: cart
                      } 
                    });
                  }}
                  disabled={hasUnavailableItems || gasProductItems.length === 0 || isProcessing}
                >
                  {isProcessing ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    `Proceed to Checkout (KSh ${total.toLocaleString()})`
                  )}
                </Button>
            </Card>
          </>
        )}
      </div>

      <BottomNav />
    </div>
  );
};

export default Cart;