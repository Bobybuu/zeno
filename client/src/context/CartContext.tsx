// src/context/CartContext.tsx - Complete fix with vendor handling
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { cartAPI } from '@/services/api';

interface CartContextType {
  cart: any;
  loading: boolean;
  refreshCart: () => Promise<void>;
  cartItemCount: number;
  cartTotal: number;
  addToCart: (productId: number, quantity?: number) => Promise<void>;
  removeFromCart: (itemId: number) => Promise<void>;
  updateCartItem: (itemId: number, quantity: number) => Promise<void>;
  clearCart: () => Promise<void>;
  createOrderFromCart: (deliveryAddress?: string) => Promise<any>; // ✅ Added this
}

const CartContext = createContext<CartContextType | undefined>(undefined);

export const CartProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [cart, setCart] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // ✅ FIXED: Improved helper function to normalize cart data
  const normalizeCartData = (cartData: any) => {
    console.log('🛒 Normalizing cart data:', cartData);
    
    // If cartData is null or undefined, return empty cart
    if (!cartData) {
      console.log('🛒 Cart data is null/undefined, using empty cart');
      return {
        items: [],
        total_amount: 0,
        item_count: 0,
        updated_at: new Date().toISOString()
      };
    }
    
    // If cartData is an array, it might be the items array directly
    if (Array.isArray(cartData)) {
      console.log('🛒 Cart data is array, converting to object format');
      const total_amount = cartData.reduce((total: number, item: any) => 
        total + (parseFloat(item.total_price?.toString() || '0') || 0), 0
      );
      const item_count = cartData.reduce((count: number, item: any) => 
        count + (parseInt(item.quantity?.toString() || '0') || 0), 0
      );
      
      return {
        items: cartData,
        total_amount,
        item_count,
        updated_at: new Date().toISOString()
      };
    }
    
    // If cartData is already an object with the expected structure
    if (cartData && typeof cartData === 'object') {
      // Ensure items is always an array
      const items = Array.isArray(cartData.items) ? cartData.items : [];
      const total_amount = parseFloat(cartData.total_amount?.toString() || '0') || 0;
      const item_count = parseInt(cartData.item_count?.toString() || '0') || 0;
      
      const normalizedCart = {
        ...cartData,
        items,
        total_amount,
        item_count,
        updated_at: cartData.updated_at || new Date().toISOString()
      };
      console.log('🛒 Normalized cart object:', normalizedCart);
      return normalizedCart;
    }
    
    // Fallback for empty or invalid data
    console.log('🛒 Using fallback empty cart');
    return {
      items: [],
      total_amount: 0,
      item_count: 0,
      updated_at: new Date().toISOString()
    };
  };

  const refreshCart = async () => {
    try {
      setLoading(true);
      console.log('🔄 refreshCart called');
      
      const cartData = await cartAPI.getCart();
      console.log('📦 Raw cart data from API:', cartData);
      
      const normalizedCart = normalizeCartData(cartData);
      console.log('✨ Normalized cart:', normalizedCart);
      
      // ✅ CRITICAL FIX: Use functional update to ensure state is set
      setCart(prevCart => {
        console.log('🔄 Setting cart state from:', prevCart, 'to:', normalizedCart);
        return normalizedCart;
      });
      
    } catch (error: any) {
      console.error('❌ Error refreshing cart:', error);
      // Set empty cart on error
      const emptyCart = {
        items: [],
        total_amount: 0,
        item_count: 0,
        updated_at: new Date().toISOString()
      };
      setCart(emptyCart);
    } finally {
      setLoading(false);
      console.log('✅ refreshCart completed, loading set to false');
    }
  };

  const addToCart = async (productId: number, quantity: number = 1) => {
    try {
      await cartAPI.addGasProduct(productId, quantity);
      await refreshCart(); // Refresh cart after adding
    } catch (error) {
      console.error('Error adding to cart:', error);
      throw error;
    }
  };

  const removeFromCart = async (itemId: number) => {
    try {
      await cartAPI.removeItem(itemId);
      await refreshCart(); // Refresh cart after removal
    } catch (error) {
      console.error('Error removing from cart:', error);
      throw error;
    }
  };

  const updateCartItem = async (itemId: number, quantity: number) => {
    try {
      await cartAPI.updateQuantity(itemId, quantity);
      await refreshCart(); // Refresh cart after update
    } catch (error) {
      console.error('Error updating cart item:', error);
      throw error;
    }
  };

  const clearCart = async () => {
    try {
      await cartAPI.clearCart();
      await refreshCart(); // Refresh cart after clear
    } catch (error) {
      console.error('Error clearing cart:', error);
      throw error;
    }
  };

  // ✅ CORRECTED: Create order from cart function - VENDOR HANDLING
  const createOrderFromCart = async (deliveryAddress: string = "Nairobi, Kenya"): Promise<any> => {
    try {
      console.log('🛒 Creating order from cart...');
      
      // Check if cart has items
      if (!cart || !cart.items || cart.items.length === 0) {
        throw new Error('Cart is empty. Cannot create order.');
      }

      const token = localStorage.getItem('access_token');
      if (!token) {
        throw new Error('User not authenticated');
      }

      console.log('📦 Cart items for order:', cart.items);

      // Debug cart items structure
      console.log('🔍 Cart items structure analysis:');
      cart.items.forEach((item: any, index: number) => {
        console.log(`Item ${index}:`, {
          id: item.id,
          item_type: item.item_type,
          gas_product: item.gas_product,
          service: item.service,
          product_id: item.product_id,
          quantity: item.quantity,
          has_gas_product: !!item.gas_product,
          has_service: !!item.service
        });
      });

      // Use the correct endpoint from your API
      const orderEndpoint = 'https://api.zenoservices.co.ke/api/orders/orders/';

      // Create order payload according to CreateMixedOrderSerializer in Django
      const orderPayload = {
        items: cart.items.map((item: any) => {
          // FIXED: Proper item type detection based on your cart structure
          const isGasProduct = !!item.gas_product;
          const isService = !!item.service;
          
          let itemType;
          let itemId;
          
          if (isGasProduct) {
            itemType = 'gas_product';
            itemId = item.gas_product;
          } else if (isService) {
            itemType = 'service';
            itemId = item.service;
          } else {
            itemType = item.item_type === 'gas_product' ? 'gas_product' : 'service';
            itemId = item.id;
          }
          
          console.log(`🔍 Item ${item.id}: type=${itemType}, id=${itemId}, quantity=${item.quantity}`);
          
          return {
            type: itemType,
            id: itemId,
            quantity: item.quantity || 1
          };
        }),
        delivery_type: 'delivery',
        delivery_address: deliveryAddress,
        special_instructions: 'Order created from cart'
      };

      console.log('🚀 Sending order payload to:', orderEndpoint);
      console.log('📦 Order payload:', JSON.stringify(orderPayload, null, 2));

      const response = await fetch(orderEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(orderPayload)
      });

      console.log('📡 Order creation response status:', response.status);

      // Check response content
      const responseText = await response.text();
      console.log('📡 Raw order creation response:', responseText);

      if (!response.ok) {
        // Handle vendor restriction error specifically
        if (responseText.includes('same vendor') || responseText.includes('All items must be from the same vendor')) {
          throw new Error(
            'MULTI_VENDOR_ERROR: Your cart contains items from different vendors. ' +
            'Please order items from one vendor at a time. ' +
            'You can remove items from other vendors and proceed with items from a single vendor.'
          );
        }
        
        let errorMessage = 'Failed to create order';
        try {
          const errorData = JSON.parse(responseText);
          errorMessage = errorData.error || errorData.detail || errorMessage;
          
          if (errorData.detail) {
            errorMessage = errorData.detail;
          } else if (typeof errorData === 'object') {
            const fieldErrors = Object.entries(errorData)
              .map(([field, errors]) => `${field}: ${Array.isArray(errors) ? errors.join(', ') : errors}`)
              .join('; ');
            if (fieldErrors) errorMessage = fieldErrors;
          }
        } catch {
          errorMessage = responseText || `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }

      if (!responseText) {
        throw new Error('Empty response from order creation');
      }

      const orderData = JSON.parse(responseText);
      console.log('✅ Order created successfully:', orderData);
      
      return orderData;
    } catch (error) {
      console.error('❌ Error creating order from cart:', error);
      throw error;
    }
  };

  useEffect(() => {
    console.log('🎯 CartProvider mounted, initializing cart...');
    refreshCart();
  }, []);

  // Add effect to log cart state changes
  useEffect(() => {
    console.log('🔄 Cart state updated:', { cart, loading });
  }, [cart, loading]);

  const value: CartContextType = {
    cart,
    loading,
    refreshCart,
    cartItemCount: cart?.item_count || 0,
    cartTotal: parseFloat(cart?.total_amount?.toString() || '0') || 0,
    addToCart,
    removeFromCart,
    updateCartItem,
    clearCart,
    createOrderFromCart // ✅ Added to context value
  };

  return (
    <CartContext.Provider value={value}>
      {children}
    </CartContext.Provider>
  );
};

export const useCart = () => {
  const context = useContext(CartContext);
  if (context === undefined) {
    throw new Error('useCart must be used within a CartProvider');
  }
  return context;
};