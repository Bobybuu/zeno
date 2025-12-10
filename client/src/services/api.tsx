// src/services/api.tsx
import axios from 'axios';

const API_BASE_URL = 'https://api.zenoservices.co.ke/api/v1'; // Update with your actual backend URL

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000, // 10 second timeout
});

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  // Check for access token only (no temp tokens)
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  
  // Ensure JSON content type for all requests
  if (!config.headers['Content-Type']) {
    config.headers['Content-Type'] = 'application/json';
  }
  
  // ✅ Add shorter timeout for cart operations
  if (config.url?.includes('/cart/')) {
    config.timeout = 8000; // 8 seconds for cart operations
  }
  
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Response interceptor to handle token refresh and errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle token refresh for 401 errors
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/users/auth/token/refresh/`, {
            refresh: refreshToken
          });
          
          const newAccessToken = response.data.access;
          localStorage.setItem('access_token', newAccessToken);
          
          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError);
        // Refresh failed, logout user
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        
        // Remove legacy items if they exist
        localStorage.removeItem('temp_access_token');
        localStorage.removeItem('temp_refresh_token');
        localStorage.removeItem('temp_user');
        
        // Redirect to login if we're not already there
        if (!window.location.pathname.includes('/login')) {
          window.location.href = '/login';
        }
      }
    }
    
    // Handle network errors
    if (!error.response) {
      console.error('Network error:', error);
      // You could show a network error notification here
    }
    
    return Promise.reject(error);
  }
);

// ============ UPDATED TYPES FOR AUTHENTICATION ============

export interface LoginData {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  password_confirm: string;
  user_type: string;
  phone_number: string;
  location?: string;
  first_name?: string;
  last_name?: string;
}

export interface VerifyEmailData {
  email: string;
  verification_code: string;
}

export interface ResendVerificationData {
  email: string;
}

export interface ChangePasswordData {
  current_password: string;
  new_password: string;
}

export interface UpdateProfileData {
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  location?: string;
  profile_picture?: File;
}

export interface ForgotPasswordData {
  email: string;
}

export interface ResetPasswordData {
  email: string;
  verification_code: string;
  new_password: string;
}

// ============ KEEP ALL OTHER TYPES EXACTLY AS THEY WERE ============

export interface ServiceFilters {
  service_type?: string;
  vendor__business_type?: string;
  lat?: number;
  lng?: number;
  radius?: number;
}

export interface VendorFilters {
  business_type?: string;
  service_type?: string;
  lat?: number;
  lng?: number;
  radius?: number;
  is_verified?: boolean;
  is_active?: boolean;
  city?: string;
}

export interface OrderFilters {
  status?: string;
  customer?: number;
  vendor?: number;
}

// Gas Products Types
export interface GasProduct {
  id: number;
  name: string;
  gas_type: string;
  cylinder_size: string;
  brand: string;
  price_with_cylinder: number;
  price_without_cylinder: number;
  cylinder_deposit?: number;
  stock_quantity: number;
  min_stock_alert: number;
  description?: string;
  ingredients?: string;
  safety_instructions?: string;
  is_available: boolean;
  is_active: boolean;
  featured: boolean;
  in_stock: boolean;
  low_stock: boolean;
  vendor: number;
  vendor_name: string;
  vendor_city: string;
  vendor_latitude?: number;
  vendor_longitude?: number;
  images: Array<{
    id: number;
    image: string;
    alt_text: string;
    is_primary: boolean;
  }>;
  created_at: string;
  updated_at: string;
}

export interface GasProductCreateData {
  name: string;
  gas_type: string;
  cylinder_size: string;
  brand?: string;
  price_with_cylinder: number;
  price_without_cylinder: number;
  stock_quantity: number;
  min_stock_alert?: number;
  description?: string;
  ingredients?: string;
  safety_instructions?: string;
  featured?: boolean;
}

export interface GasProductUpdateData {
  name?: string;
  brand?: string;
  price_with_cylinder?: number;
  price_without_cylinder?: number;
  stock_quantity?: number;
  min_stock_alert?: number;
  description?: string;
  ingredients?: string;
  safety_instructions?: string;
  is_active?: boolean;
  featured?: boolean;
}

export interface GasProductFilters {
  gas_type?: string;
  cylinder_size?: string;
  vendor?: number;
  is_available?: boolean;
  featured?: boolean;
  min_price?: number;
  max_price?: number;
  city?: string;
  lat?: number;
  lng?: number;
  radius?: number;
  vendor__is_verified?: boolean;
}

export interface Vendor {
  id: number;
  user: number;
  business_name: string;
  business_type: string;
  description?: string;
  latitude?: number;
  longitude?: number;
  address: string;
  city: string;
  country: string;
  contact_number: string;
  email?: string;
  website?: string;
  opening_hours?: string;
  is_verified: boolean;
  is_active: boolean;
  average_rating: number;
  total_reviews: number;
  delivery_radius_km: number;
  min_order_amount: number;
  delivery_fee: number;
  total_gas_products?: number;
  available_gas_products?: number;
  operating_hours: Array<{
    id: number;
    day: number;
    opening_time: string;
    closing_time: string;
    is_closed: boolean;
  }>;
  reviews: Array<{
    id: number;
    customer: number;
    customer_name: string;
    rating: number;
    comment: string;
    created_at: string;
  }>;
  created_at: string;
  updated_at: string;
}

export interface VendorCreateData {
  business_name: string;
  business_type: string;
  description?: string;
  latitude?: number;
  longitude?: number;
  address: string;
  city: string;
  country?: string;
  contact_number: string;
  email?: string;
  website?: string;
  delivery_radius_km?: number;
  min_order_amount?: number;
  delivery_fee?: number;
}

export interface VendorUpdateData {
  business_name?: string;
  description?: string;
  latitude?: number;
  longitude?: number;
  address?: string;
  city?: string;
  contact_number?: string;
  email?: string;
  website?: string;
  opening_hours?: string;
  delivery_radius_km?: number;
  min_order_amount?: number;
  delivery_fee?: number;
}

export interface VendorReviewData {
  rating: number;
  comment?: string;
}

export interface OperatingHoursData {
  day: number;
  opening_time: string;
  closing_time: string;
  is_closed?: boolean;
}

export interface CartItem {
  product_id: number;
  quantity: number;
  include_cylinder: boolean;
  product?: GasProduct;
}

export interface OrderItem {
  product: number;
  quantity: number;
  unit_price: number;
  include_cylinder: boolean;
}

export interface CreateOrderData {
  vendor: number;
  items: OrderItem[];
  delivery_address?: string;
  delivery_latitude?: number;
  delivery_longitude?: number;
  special_instructions?: string;
}

// ============ UPDATED AUTH API ============

export const authAPI = {
  // Authentication - UPDATED ENDPOINTS
  login: (credentials: LoginData) => api.post('/users/auth/login/', credentials),
  register: (userData: RegisterData) => api.post('/users/auth/register/', userData),
  
  // Email verification - NEW ENDPOINTS
  verifyEmail: (data: VerifyEmailData) => api.post('/users/auth/verify-email/', data),
  resendVerification: (data: ResendVerificationData) => api.post('/users/auth/resend-verification/', data),
  
  // Session & Profile - UPDATED ENDPOINTS
  checkAuth: () => api.get('/users/me/'),
  logout: (data?: any) => api.post('/users/auth/logout/', data),
  getProfile: () => api.get('/users/me/'),
  updateProfile: (data: UpdateProfileData) => {
    const formData = new FormData();
    if (data.first_name) formData.append('first_name', data.first_name);
    if (data.last_name) formData.append('last_name', data.last_name);
    if (data.phone_number) formData.append('phone_number', data.phone_number);
    if (data.location) formData.append('location', data.location);
    if (data.profile_picture) formData.append('profile_picture', data.profile_picture);
    
    return api.put('/users/me/update/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  
  // Password management - UPDATED ENDPOINTS
  changePassword: (data: ChangePasswordData) => api.post('/users/auth/password/change/', data),
  forgotPassword: (data: ForgotPasswordData) => api.post('/users/auth/password/reset/', data),
  resetPassword: (data: ResetPasswordData) => api.post('/users/auth/password/reset/confirm/', data),
  
  // Token refresh - UPDATED ENDPOINT
  refreshToken: (refresh: string) => api.post('/users/auth/token/refresh/', { refresh }),
  
  // REMOVED: OTP endpoints
  // verifyOTP: (data: VerifyOTPData) => api.post('/auth/verify-otp/', data), - REMOVED
  // resendOTP: (data: ResendOTPData) => api.post('/auth/resend-otp/', data), - REMOVED
  // verifyResetCode: (data: VerifyResetCodeData) => api.post('/auth/verify-reset-code/', data), - REMOVED
};

// ============ SERVICES API - KEEP EXACTLY AS IT WAS ============

export const servicesAPI = {
  getServices: (filters?: ServiceFilters) => api.get('/services/', { params: filters }),
  getService: (id: number) => api.get(`/services/${id}/`),
  createService: (data: any) => api.post('/services/', data),
  updateService: (id: number, data: any) => api.put(`/services/${id}/`, data),
  deleteService: (id: number) => api.delete(`/services/${id}/`),
};

// ============ VENDORS API - KEEP EXACTLY AS IT WAS ============

export const vendorsAPI = {
  // Vendor management
  getVendors: (filters?: VendorFilters) => api.get('/vendors/vendors/', { params: filters }),
  getVendor: (id: number) => api.get(`/vendors/vendors/${id}/`),
  getMyVendor: () => api.get('/vendors/vendors/my_vendor/'),
  registerVendor: (data: VendorCreateData) => api.post('/vendors/vendors/', data),
  updateVendor: (id: number, data: VendorUpdateData) => api.patch(`/vendors/vendors/${id}/`, data),
  getVendorDashboard: () => api.get('/vendors/vendors/my_vendor/vendor_dashboard/'),
  
  // Vendor location and discovery
  getNearbyVendors: (lat: number, lng: number, radius: number = 10, business_type?: string) => 
    api.get('/vendors/vendors/nearby_vendors/', { 
      params: { lat, lng, radius, business_type } 
    }),
  
  // Vendor with products
  getVendorWithProducts: (id: number) => api.get(`/vendors/vendors/${id}/vendor_with_products/`),
  
  // Reviews
  getVendorReviews: (vendorId: number) => api.get(`/vendors/reviews/vendor_reviews/?vendor=${vendorId}`),
  createReview: (vendorId: number, data: VendorReviewData) => api.post('/vendors/reviews/', { ...data, vendor: vendorId }),
  updateReview: (reviewId: number, data: VendorReviewData) => api.put(`/vendors/reviews/${reviewId}/`, data),
  deleteReview: (reviewId: number) => api.delete(`/vendors/reviews/${reviewId}/`),
  
  // Operating hours
  getOperatingHours: (vendorId: number) => api.get('/vendors/operating-hours/', { params: { vendor: vendorId } }),
  createOperatingHours: (data: OperatingHoursData) => api.post('/vendors/operating-hours/', data),
  updateOperatingHours: (id: number, data: OperatingHoursData) => api.put(`/vendors/operating-hours/${id}/`, data),
  deleteOperatingHours: (id: number) => api.delete(`/vendors/operating-hours/${id}/`),
};

// ============ GAS PRODUCTS API - KEEP EXACTLY AS IT WAS ============

export const gasProductsAPI = {
  // Product management
  getGasProducts: (filters?: GasProductFilters) => api.get('/vendors/gas-products/', { params: filters }),
  getGasProduct: (id: number) => api.get(`/vendors/gas-products/${id}/`),
  createGasProduct: (data: GasProductCreateData) => api.post('/vendors/gas-products/', data),
  updateGasProduct: (id: number, data: GasProductUpdateData) => api.patch(`/vendors/gas-products/${id}/`, data),
  deleteGasProduct: (id: number) => api.delete(`/vendors/gas-products/${id}/`),
  
  // Vendor-specific products
  getMyProducts: () => api.get('/vendors/gas-products/my_products/'),
  
  // Product actions
  updateStock: (id: number, stockQuantity: number, minStockAlert?: number) => 
    api.patch(`/vendors/gas-products/${id}/update_stock/`, { stock_quantity: stockQuantity, min_stock_alert: minStockAlert }),
  
  toggleAvailability: (id: number) => 
    api.post(`/vendors/gas-products/${id}/toggle_availability/`),
  
  // Product discovery
  getFeaturedProducts: () => api.get('/vendors/gas-products/featured_products/'),
  
  searchProducts: (query: string, filters?: GasProductFilters) => 
    api.get('/vendors/gas-products/search_products/', { 
      params: { search: query, ...filters } 
    }),
  
  // Product images
  uploadProductImage: (productId: number, imageFile: File, altText?: string, isPrimary?: boolean) => {
    const formData = new FormData();
    formData.append('product', productId.toString());
    formData.append('image', imageFile);
    if (altText) formData.append('alt_text', altText);
    if (isPrimary) formData.append('is_primary', isPrimary.toString());
    
    return api.post('/vendors/product-images/', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  
  deleteProductImage: (imageId: number) => api.delete(`/vendors/product-images/${imageId}/`),
  setPrimaryImage: (imageId: number) => api.post(`/vendors/product-images/${imageId}/set_primary/`),
};

// ============ ORDERS API - KEEP EXACTLY AS IT WAS ============

export const ordersAPI = {
  getOrders: (filters?: OrderFilters) => api.get('/orders/', { params: filters }),
  getOrder: (id: number) => api.get(`/orders/${id}/`),
  createOrder: (data: CreateOrderData) => api.post('/orders/', data),
  updateOrder: (id: number, data: any) => api.put(`/orders/${id}/`, data),
  cancelOrder: (id: number) => api.post(`/orders/${id}/cancel/`),
  
  // Customer orders
  getMyOrders: () => api.get('/orders/my_orders/'),
  
  // Vendor orders
  getVendorOrders: () => api.get('/orders/vendor_orders/'),
  updateOrderStatus: (orderId: number, status: string) => 
    api.patch(`/orders/${orderId}/update_status/`, { status }),
};

// ============ PAYMENTS API - KEEP EXACTLY AS IT WAS ============

export const paymentsAPI = {
  createPayment: (data: any) => api.post('/payments/', data),
  getPayment: (id: number) => api.get(`/payments/${id}/`),
  verifyPayment: (id: number) => api.post(`/payments/${id}/verify/`),
  
  // Order payments
  createOrderPayment: (orderId: number, paymentMethod: string) => 
    api.post('/payments/create_order_payment/', { order: orderId, payment_method: paymentMethod }),
};

// ============ CART API - KEEP EXACTLY AS IT WAS ============

export const cartAPI = {
  // Get user's cart from backend
  getCart: async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const response = await api.get('/orders/cart/my_cart/');
        console.log('🛒 Backend cart response:', response.data);
        return response.data;
      } else {
        // Fallback to localStorage for guest users
        return cartAPI.getLocalStorageCart();
      }
    } catch (error: any) {
      console.error('Error fetching cart from backend:', error);
      
      // If it's a timeout or network error, fallback to localStorage
      if (error.code === 'ECONNABORTED' || !error.response) {
        console.log('🛒 Using localStorage fallback due to timeout');
        return cartAPI.getLocalStorageCart();
      }
      
      // For 401 errors, user might not be properly authenticated
      if (error.response?.status === 401) {
        console.log('🛒 User not authenticated, using localStorage');
        return cartAPI.getLocalStorageCart();
      }
      
      // For other errors, still fallback to localStorage
      return cartAPI.getLocalStorageCart();
    }
  },

  // Add gas product to cart
  addGasProduct: async (productId: number, quantity: number = 1) => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        console.log('🛒 Adding to backend cart:', { productId, quantity });
        const response = await api.post('/orders/cart/add_gas_product/', {
          product_id: productId,
          quantity: quantity
        });
        console.log('🛒 Backend add to cart response:', response.data);
        return response.data;
      } else {
        console.log('🛒 Adding to localStorage cart:', { productId, quantity });
        const result = cartAPI.addToLocalStorage(productId, quantity);
        console.log('🛒 localStorage cart after add:', result);
        return result;
      }
    } catch (error: any) {
      console.error('Error adding to cart:', error);
      
      if (error.response?.status === 401) {
        throw new Error('Please log in to add items to cart');
      } else if (error.code === 'ECONNABORTED' || !error.response) {
        console.log('🛒 Backend timeout, using localStorage fallback');
        const result = cartAPI.addToLocalStorage(productId, quantity);
        console.log('🛒 localStorage cart after fallback:', result);
        return result;
      } else {
        console.log('🛒 Other error, using localStorage fallback');
        const result = cartAPI.addToLocalStorage(productId, quantity);
        console.log('🛒 localStorage cart after error fallback:', result);
        return result;
      }
    }
  },

  // Update item quantity
  updateQuantity: async (itemId: number, quantity: number) => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const response = await api.post('/orders/cart/update_quantity/', {
          item_id: itemId,
          quantity: quantity
        });
        return response.data;
      } else {
        return cartAPI.updateLocalStorageItem(itemId, quantity);
      }
    } catch (error: any) {
      console.error('Error updating quantity:', error);
      if (error.code === 'ECONNABORTED' || !error.response) {
        return cartAPI.updateLocalStorageItem(itemId, quantity);
      }
      throw error;
    }
  },

  // Remove item from cart
  removeItem: async (itemId: number) => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const response = await api.post('/orders/cart/remove_item/', {
          item_id: itemId
        });
        return response.data;
      } else {
        return cartAPI.removeFromLocalStorage(itemId);
      }
    } catch (error: any) {
      console.error('Error removing item:', error);
      if (error.code === 'ECONNABORTED' || !error.response) {
        return cartAPI.removeFromLocalStorage(itemId);
      }
      throw error;
    }
  },

  // Clear entire cart
  clearCart: async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const response = await api.post('/orders/cart/clear/');
        return response.data;
      } else {
        return cartAPI.clearLocalStorage();
      }
    } catch (error: any) {
      console.error('Error clearing cart:', error);
      if (error.code === 'ECONNABORTED' || !error.response) {
        return cartAPI.clearLocalStorage();
      }
      throw error;
    }
  },

  // ✅ FIXED: Improved localStorage helper functions with array detection
  getLocalStorageCart: () => {
    try {
      const cart = localStorage.getItem('gaslink_cart');
      if (cart) {
        const parsedCart = JSON.parse(cart);
        console.log('🛒 LocalStorage cart:', parsedCart);
        
        // ✅ Handle case where cart is stored as array instead of object
        if (Array.isArray(parsedCart)) {
          console.log('🛒 Converting array cart to object format');
          const convertedCart = {
            items: parsedCart,
            total_amount: parsedCart.reduce((sum: number, item: any) => sum + (item.total_price || 0), 0),
            item_count: parsedCart.reduce((count: number, item: any) => count + (item.quantity || 0), 0),
            updated_at: new Date().toISOString()
          };
          // Save the corrected format back to localStorage
          localStorage.setItem('gaslink_cart', JSON.stringify(convertedCart));
          return convertedCart;
        }
        
        return parsedCart;
      }
    } catch (error) {
      console.error('Error reading localStorage cart:', error);
    }
    
    // Return empty cart structure
    const emptyCart = {
      items: [],
      total_amount: 0,
      item_count: 0,
      updated_at: new Date().toISOString()
    };
    console.log('🛒 Created new empty cart');
    return emptyCart;
  },

  // ✅ FIXED: Improved addToLocalStorage with proper structure validation
  addToLocalStorage: (productId: number, quantity: number = 1) => {
    const cart = cartAPI.getLocalStorageCart();
    
    // ✅ Ensure cart has the correct structure
    if (!cart.items) {
      cart.items = [];
    }
    if (cart.total_amount === undefined) {
      cart.total_amount = 0;
    }
    if (cart.item_count === undefined) {
      cart.item_count = 0;
    }
    
    // Check if product already exists in cart
    const existingItemIndex = cart.items.findIndex((item: any) => 
      item.gas_product === productId || item.product_id === productId
    );
    
    if (existingItemIndex > -1) {
      cart.items[existingItemIndex].quantity += quantity;
      if (cart.items[existingItemIndex].unit_price) {
        cart.items[existingItemIndex].total_price = 
          cart.items[existingItemIndex].unit_price * cart.items[existingItemIndex].quantity;
      }
    } else {
      const newItem = {
        id: Date.now(),
        item_type: 'gas_product',
        gas_product: productId,
        product_id: productId, // Add both for compatibility
        quantity: quantity,
        unit_price: 0, // Will be updated when product details are fetched
        total_price: 0,
        added_at: new Date().toISOString(),
        item_name: 'Gas Product'
      };
      cart.items.push(newItem);
    }
    
    // Update cart totals
    cart.total_amount = cart.items.reduce((sum: number, item: any) => sum + (item.total_price || 0), 0);
    cart.item_count = cart.items.reduce((count: number, item: any) => count + (item.quantity || 0), 0);
    cart.updated_at = new Date().toISOString();
    
    localStorage.setItem('gaslink_cart', JSON.stringify(cart));
    console.log('🛒 Updated localStorage cart:', cart);
    return cart;
  },

  updateLocalStorageItem: (itemId: number, quantity: number) => {
    const cart = cartAPI.getLocalStorageCart();
    const itemIndex = cart.items.findIndex((item: any) => item.id === itemId);
    
    if (itemIndex > -1) {
      if (quantity <= 0) {
        cart.items.splice(itemIndex, 1);
      } else {
        cart.items[itemIndex].quantity = quantity;
        if (cart.items[itemIndex].unit_price) {
          cart.items[itemIndex].total_price = cart.items[itemIndex].unit_price * quantity;
        }
      }
    }
    
    // Update cart totals
    cart.total_amount = cart.items.reduce((sum: number, item: any) => sum + (item.total_price || 0), 0);
    cart.item_count = cart.items.reduce((count: number, item: any) => count + (item.quantity || 0), 0);
    cart.updated_at = new Date().toISOString();
    
    localStorage.setItem('gaslink_cart', JSON.stringify(cart));
    return cart;
  },

  removeFromLocalStorage: (itemId: number) => {
    const cart = cartAPI.getLocalStorageCart();
    cart.items = cart.items.filter((item: any) => item.id !== itemId);
    
    // Update cart totals
    cart.total_amount = cart.items.reduce((sum: number, item: any) => sum + (item.total_price || 0), 0);
    cart.item_count = cart.items.reduce((count: number, item: any) => count + (item.quantity || 0), 0);
    cart.updated_at = new Date().toISOString();
    
    localStorage.setItem('gaslink_cart', JSON.stringify(cart));
    return cart;
  },

  clearLocalStorage: () => {
    const emptyCart = {
      items: [],
      total_amount: 0,
      item_count: 0,
      updated_at: new Date().toISOString()
    };
    localStorage.setItem('gaslink_cart', JSON.stringify(emptyCart));
    return emptyCart;
  },

  // Get cart total for display
  getCartTotal: async () => {
    const cart = await cartAPI.getCart();
    return parseFloat(cart.total_amount) || 0;
  },

  // Get cart item count for badge
  getCartItemCount: async () => {
    const cart = await cartAPI.getCart();
    return cart.item_count || 0;
  }
};

// ============ UTILITY FUNCTIONS - UPDATED ============

export const isAuthenticated = (): boolean => {
  return !!localStorage.getItem('access_token');
};

export const getToken = (): string | null => {
  return localStorage.getItem('access_token');
};

export const clearAuthData = (): void => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
  // Also clear any pending verification data
  localStorage.removeItem('pending_user_email');
  // Remove legacy items if they exist
  localStorage.removeItem('temp_access_token');
  localStorage.removeItem('temp_refresh_token');
  localStorage.removeItem('temp_user');
};

// Helper function for file uploads - KEEP AS WAS
export const uploadFile = (file: File, uploadUrl: string, onProgress?: (progress: number) => void) => {
  const formData = new FormData();
  formData.append('file', file);

  return api.post(uploadUrl, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const progress = (progressEvent.loaded / progressEvent.total) * 100;
        onProgress(progress);
      }
    },
  });
};

// Health API - UPDATED ENDPOINT
export const healthAPI = {
  checkBackendHealth: () => api.get('/users/health/'),
  checkCartHealth: () => api.get('/orders/cart/health/', { timeout: 5000 })
};

// Safe Gas Products API - KEEP EXACTLY AS WAS
export const safeGasProductsAPI = {
  getGasProducts: async (filters?: GasProductFilters) => {
    try {
      // Remove problematic filters that might cause 500 errors
      const safeFilters = { ...filters };
      
      // Don't send empty or undefined values
      Object.keys(safeFilters).forEach(key => {
        if (safeFilters[key as keyof GasProductFilters] === undefined || safeFilters[key as keyof GasProductFilters] === '') {
          delete safeFilters[key as keyof GasProductFilters];
        }
      });

      // Ensure boolean values are properly formatted
      if (safeFilters.is_available !== undefined) {
        safeFilters.is_available = Boolean(safeFilters.is_available);
      }
      if (safeFilters.vendor__is_verified !== undefined) {
        safeFilters.vendor__is_verified = Boolean(safeFilters.vendor__is_verified);
      }

      console.log('Making API call with filters:', safeFilters);
      
      const response = await api.get('/vendors/gas-products/', { 
        params: safeFilters,
        paramsSerializer: (params) => {
          return Object.entries(params)
            .map(([key, value]) => {
              if (value === null || value === undefined) return '';
              return `${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
            })
            .filter(Boolean)
            .join('&');
        }
      });
      
      return response.data;
    } catch (error: any) {
      console.error('Error in safeGasProductsAPI.getGasProducts:', error);
      
      // If there's a 500 error, try without location filters
      if (error.response?.status === 500 && filters?.lat && filters?.lng) {
        console.log('Retrying without location filters...');
        const { lat, lng, radius, ...retryFilters } = filters;
        return gasProductsAPI.getGasProducts(retryFilters);
      }
      
      throw error;
    }
  }
};

export default api;