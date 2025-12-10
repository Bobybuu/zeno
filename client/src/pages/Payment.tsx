// src/pages/Payment.tsx - Complete Fixed Version
import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { ArrowLeft, CreditCard, Phone, Loader2, Shield, CheckCircle2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/ui/use-toast";
import BottomNav from "@/components/BottomNav";
import { useCart } from "@/context/CartContext";

interface OrderItem {
  id: number;
  productId: number;
  productName: string;
  vendorName: string;
  quantity: number;
  unitPrice: number;
  totalAmount: number;
  includeCylinder: boolean;
  description?: string;
}

interface PaymentState {
  orderItems: OrderItem[];
  totalAmount: number;
  cartData?: any;
}

interface PaymentResponse {
  message: string;
  checkout_request_id: string;
  payment_id: number;
}

interface PaymentStatusResponse {
  status: 'pending' | 'processing' | 'completed' | 'failed';
  payment_id: number;
  order_id: number;
  amount?: number;
}

const Payment = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const { createOrderFromCart, clearCart } = useCart();
  
  const [phoneNumber, setPhoneNumber] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [paymentStatus, setPaymentStatus] = useState<'idle' | 'processing' | 'success' | 'failed'>('idle');
  const [currentPayment, setCurrentPayment] = useState<PaymentResponse | null>(null);
  const [orderItems, setOrderItems] = useState<OrderItem[]>([]);
  const [orderId, setOrderId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [pollingInterval]);

  // Initialize payment data
  useEffect(() => {
    const initializePayment = async () => {
      try {
        const state = location.state as PaymentState;
        
        if (state?.orderItems && state.orderItems.length > 0) {
          console.log('🛒 Payment received order items:', state.orderItems);
          setOrderItems(state.orderItems);
          
          // ✅ Use the CartContext function to create order
          const orderData = await createOrderFromCart("Nairobi, Kenya");
          setOrderId(orderData.id);
          
          console.log('✅ Order created for payment:', orderData);
        } else {
          setError('No items found for payment');
          toast({
            title: "No Items",
            description: "No items found for payment",
            variant: "destructive"
          });
          navigate('/cart');
        }
      } catch (error) {
        console.error('❌ Error initializing payment:', error);
        const errorMessage = error instanceof Error ? error.message : "Failed to initialize payment";
        setError(errorMessage);
        
        // Check if it's a vendor error
        if (errorMessage.includes('MULTI_VENDOR_ERROR') || errorMessage.includes('same vendor')) {
          toast({
            title: "Multiple Vendors Detected",
            description: "Your cart contains items from different vendors. Please order from one vendor at a time.",
            variant: "destructive",
            duration: 10000,
            action: (
              <Button 
                variant="outline" 
                onClick={() => navigate('/cart')}
                className="text-white border-white"
              >
                Review Cart
              </Button>
            )
          });
        } else {
          toast({
            title: "Error",
            description: errorMessage,
            variant: "destructive"
          });
        }
        navigate('/cart');
      } finally {
        setLoading(false);
      }
    };

    initializePayment();
  }, [location.state, createOrderFromCart, navigate, toast]);

  const formatPhoneNumber = (number: string): string => {
    let cleaned = number.replace(/\D/g, '');
    
    if (cleaned.startsWith('0')) {
      cleaned = '254' + cleaned.substring(1);
    } else if (!cleaned.startsWith('254')) {
      cleaned = '254' + cleaned;
    }
    
    return cleaned;
  };

  const validatePhoneNumber = (number: string): boolean => {
    const formatted = formatPhoneNumber(number);
    return formatted.length === 12;
  };

  // Helper function to get existing payment ID
  const getExistingPaymentId = async (orderId: number, token: string): Promise<number | null> => {
    try {
      console.log('🔍 Looking for existing payment for order:', orderId);
      
      // Try to get payment details from the orders endpoint
      const orderResponse = await fetch(`https://api.implimenta.store/api/orders/orders/${orderId}/`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (orderResponse.ok) {
        const orderData = await orderResponse.json();
        console.log('🔍 Order data:', orderData);
        
        // Check if order has payment information
        if (orderData.payment_status === 'paid' || orderData.payment_status === 'processing') {
          console.log('✅ Order payment status:', orderData.payment_status);
          
          // Try to find the payment ID from payments endpoint
          const paymentsResponse = await fetch('https://api.implimenta.store/api/payments/payments/', {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });

          if (paymentsResponse.ok) {
            const paymentsData = await paymentsResponse.json();
            console.log('🔍 Payments data:', paymentsData);
            
            // Look for payment with this order ID
            if (paymentsData.results && Array.isArray(paymentsData.results)) {
              const existingPayment = paymentsData.results.find((payment: any) => 
                payment.order === orderId || payment.order_id === orderId
              );
              
              if (existingPayment) {
                console.log('✅ Found existing payment:', existingPayment);
                return existingPayment.id;
              }
            }
          }
        }
      }
      
      return null;
    } catch (error) {
      console.error('❌ Error finding existing payment:', error);
      return null;
    }
  };

  const handlePayment = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!phoneNumber || !validatePhoneNumber(phoneNumber)) {
      toast({
        title: "Invalid Phone Number",
        description: "Please enter a valid Kenyan phone number (e.g., 0712345678)",
        variant: "destructive"
      });
      return;
    }

    if (!orderId) {
      toast({
        title: "No Order",
        description: "Please wait while we create your order",
        variant: "destructive"
      });
      return;
    }

    setIsProcessing(true);
    setPaymentStatus('processing');
    setError(null);

    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        throw new Error('Authentication required. Please log in again.');
      }

      const formattedPhone = formatPhoneNumber(phoneNumber);

      console.log('💰 Initiating payment for order:', orderId);
      console.log('💰 Using phone number:', formattedPhone);

      // Use the correct payment endpoint
      const paymentEndpoint = 'https://api.implimenta.store/api/payments/initiate-payment/';

      const paymentPayload = {
        order_id: orderId,
        phone_number: formattedPhone,
        payment_method: 'mpesa'
      };

      console.log('💰 Payment payload:', paymentPayload);
      console.log('💰 Using endpoint:', paymentEndpoint);

      const response = await fetch(paymentEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(paymentPayload)
      });

      console.log('💰 Payment response status:', response.status);
      console.log('💰 Payment response headers:', Object.fromEntries(response.headers.entries()));

      const responseText = await response.text();
      console.log('💰 Raw response text:', responseText);
      console.log('💰 Response text length:', responseText.length);

      if (!response.ok) {
        // Handle specific payment errors
        let errorMessage = 'Failed to initiate payment';
        
        try {
          const errorData = JSON.parse(responseText);
          errorMessage = errorData.error || errorData.detail || errorMessage;
          
          // Handle "payment already exists" error specifically
          if (errorMessage.includes('Payment already initiated') || errorMessage.includes('already exists')) {
            errorMessage = 'Payment already initiated for this order. Please check your phone for the M-Pesa prompt.';
            
            // If payment already exists, we can still proceed to polling
            console.log('🔄 Payment already initiated, proceeding to polling...');
            
            // Try to get the existing payment ID from the order
            const paymentId = await getExistingPaymentId(orderId, token);
            if (paymentId) {
              console.log('✅ Found existing payment ID:', paymentId);
              startPaymentPolling(paymentId);
              
              toast({
                title: "Payment Already Initiated",
                description: "Payment was already started. Checking status...",
              });
              
              return; // Exit early, polling will handle the rest
            }
          }
        } catch {
          errorMessage = responseText || `HTTP ${response.status}: ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }

      if (!responseText) {
        throw new Error('Empty response from payment server');
      }

      const paymentData: PaymentResponse = JSON.parse(responseText);
      console.log('✅ Payment initiated successfully:', paymentData);
      
      setCurrentPayment(paymentData);
      toast({
        title: "Payment Initiated",
        description: "Check your phone to complete the M-Pesa payment",
      });

      // Start polling for payment status
      startPaymentPolling(paymentData.payment_id);
      
    } catch (error) {
      console.error('❌ Payment initiation failed:', error);
      const errorMessage = error instanceof Error ? error.message : "Failed to initiate payment. Please try again.";
      setError(errorMessage);
      setPaymentStatus('failed');
      
      toast({
        title: "Payment Failed",
        description: errorMessage,
        variant: "destructive"
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const startPaymentPolling = (paymentId: number) => {
    console.log(`💰 Starting payment polling for payment ID: ${paymentId}`);
    
    // Clear any existing polling
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }

    let pollCount = 0;
    const maxPolls = 40; // 2 minutes at 3-second intervals
    let isCompleted = false;
    
    const interval = setInterval(async () => {
      if (isCompleted) {
        clearInterval(interval);
        return;
      }

      pollCount++;
      console.log(`💰 Payment poll ${pollCount}/${maxPolls} for payment ID: ${paymentId}`);
      
      try {
        const token = localStorage.getItem('access_token');
        
        const statusEndpoint = `https://api.implimenta.store/api/payments/payment-status/${paymentId}/`;
        
        console.log(`💰 Polling payment status via: ${statusEndpoint}`);
        
        const response = await fetch(statusEndpoint, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });

        console.log(`💰 Status response: ${response.status}`);

        if (response.ok) {
          const responseText = await response.text();
          if (responseText) {
            const paymentStatusData: PaymentStatusResponse = JSON.parse(responseText);
            console.log('💰 Payment status check result:', paymentStatusData);
            
            if (paymentStatusData.status === 'completed') {
              isCompleted = true;
              clearInterval(interval);
              setPaymentStatus('success');
              console.log('✅ Payment completed successfully!');
              toast({
                title: "Payment Successful!",
                description: "Your payment has been confirmed",
              });
              
              // ✅ Clear cart and navigate to success page
              setTimeout(() => {
                clearCart();
                navigate("/order-confirmation", { 
                  state: { 
                    orderItems: orderItems,
                    orderId: orderId,
                    totalAmount: grandTotal,
                    paymentId: paymentId
                  } 
                });
              }, 2000);
              
            } else if (paymentStatusData.status === 'failed') {
              isCompleted = true;
              clearInterval(interval);
              setPaymentStatus('failed');
              console.log('❌ Payment failed');
              toast({
                title: "Payment Failed",
                description: "The payment was not completed. Please try again.",
                variant: "destructive"
              });
              
            } else {
              console.log(`💰 Payment still processing. Status: ${paymentStatusData.status}`);
              
              // Show progress to user
              if (pollCount % 5 === 0) { // Every 15 seconds
                toast({
                  title: "Payment Processing",
                  description: `Still waiting for payment confirmation... (${pollCount * 3}s)`,
                  duration: 3000,
                });
              }
            }
          }
        } else {
          console.log(`❌ Status check failed: ${response.status}`);
        }
      } catch (error) {
        console.error('Error polling payment status:', error);
      }
      
      // Stop if max polls reached
      if (pollCount >= maxPolls && !isCompleted) {
        isCompleted = true;
        clearInterval(interval);
        setPaymentStatus('failed');
        console.log('💰 Maximum polling attempts reached');
        toast({
          title: "Payment Timeout",
          description: "Payment took too long to complete. Please check your phone and try again if needed.",
          variant: "destructive"
        });
      }
    }, 3000); // Poll every 3 seconds

    setPollingInterval(interval);
  };

  const retryPayment = () => {
    console.log('🔄 Retrying payment...');
    
    // Clear any existing polling
    if (pollingInterval) {
      clearInterval(pollingInterval);
      setPollingInterval(null);
    }
    
    setPaymentStatus('idle');
    setCurrentPayment(null);
    setError(null);
  };

  const debugEndpoints = async () => {
    console.log('🔍 Manual endpoint debugging triggered...');
    
    const endpoints = [
      'https://api.zenoservices.co.ke/api/payments/',
      'https://api.zenoservices.co.ke/api/payments/initiate-payment/',
    ];

    const token = localStorage.getItem('access_token');
    
    for (const endpoint of endpoints) {
      try {
        console.log(`🔍 Testing: ${endpoint}`);
        const response = await fetch(endpoint, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });
        console.log(`🔍 ${endpoint} - Status: ${response.status}, OK: ${response.ok}`);
        
        if (response.ok) {
          const data = await response.json();
          console.log(`🔍 ${endpoint} - Success:`, data);
        } else {
          console.log(`🔍 ${endpoint} - Error: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.log(`🔍 ${endpoint} - Fetch Error:`, error);
      }
    }
  };

  const calculateTotal = (): number => {
    return orderItems.reduce((total, item) => total + item.totalAmount, 0);
  };

  const total = calculateTotal();
  const deliveryFee = 200;
  const grandTotal = total + deliveryFee;

  if (loading) {
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading payment details...</p>
        </div>
      </div>
    );
  }

  if (error && !orderItems.length) {
    const isVendorError = error.includes('MULTI_VENDOR_ERROR') || error.includes('same vendor');
    
    return (
      <div className="min-h-screen bg-background pb-20 flex items-center justify-center">
        <div className="text-center p-4 max-w-md">
          {isVendorError ? (
            <>
              <AlertTriangle className="h-16 w-16 text-yellow-500 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-yellow-900 mb-2">Multiple Vendors Detected</h3>
              <p className="text-yellow-700 mb-6">
                Your cart contains items from different vendors. Please order from one vendor at a time.
              </p>
            </>
          ) : (
            <>
              <div className="text-6xl mb-4">❌</div>
              <h3 className="text-lg font-semibold mb-2">Payment Error</h3>
              <p className="text-muted-foreground mb-6">{error}</p>
              <Button 
                variant="outline" 
                onClick={debugEndpoints}
                className="mb-4"
              >
                Debug Endpoints
              </Button>
            </>
          )}
          
          <div className="space-y-3">
            <Button 
              onClick={() => navigate('/cart')}
              className="w-full"
            >
              Back to Cart
            </Button>
            {!isVendorError && (
              <Button 
                variant="outline" 
                onClick={retryPayment}
                className="w-full"
              >
                Try Again
              </Button>
            )}
          </div>
        </div>
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
            onClick={() => navigate(-1)}
            className="text-white hover:bg-white/20"
            disabled={isProcessing || paymentStatus === 'processing'}
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-semibold">Payment</h1>
          
        </div>
      </header>

      <div className="p-4 space-y-4">
        {/* Payment Status Display */}
        {paymentStatus === 'processing' && (
          <Card className="p-4 bg-blue-50 border-blue-200">
            <div className="flex items-center gap-3">
              <Loader2 className="h-5 w-5 animate-spin text-blue-600" />
              <div>
                <h3 className="font-semibold text-blue-900">Processing Payment</h3>
                <p className="text-sm text-blue-700">
                  Check your phone for M-Pesa prompt. Enter your PIN to complete payment.
                </p>
                <p className="text-xs text-blue-600 mt-1">
                  Order: {orderId} | Polling active...
                </p>
              </div>
            </div>
          </Card>
        )}

        {paymentStatus === 'success' && (
          <Card className="p-4 bg-green-50 border-green-200">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600" />
              <div>
                <h3 className="font-semibold text-green-900">Payment Successful!</h3>
                <p className="text-sm text-green-700">
                  Your payment has been confirmed. Redirecting...
                </p>
              </div>
            </div>
          </Card>
        )}

        {paymentStatus === 'failed' && currentPayment && (
          <Card className="p-4 bg-red-50 border-red-200">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              <div>
                <h3 className="font-semibold text-red-900">Payment Failed</h3>
                <p className="text-sm text-red-700">
                  The payment was not completed. Please try again.
                </p>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="mt-2"
                  onClick={retryPayment}
                >
                  Try Again
                </Button>
              </div>
            </div>
          </Card>
        )}

        {/* Order Summary */}
        <Card className="p-4">
          <h3 className="font-semibold mb-3">Order Summary</h3>
          <div className="space-y-3">
            {orderItems.map((item, index) => (
              <div key={`${item.productId}-${index}`} className="flex justify-between items-start">
                <div className="flex-1">
                  <p className="font-medium">{item.productName}</p>
                  <p className="text-sm text-muted-foreground">
                    {item.vendorName} × {item.quantity}
                    {item.includeCylinder && " • With Cylinder"}
                  </p>
                  {item.description && (
                    <p className="text-xs text-muted-foreground">{item.description}</p>
                  )}
                </div>
                <span className="font-semibold">
                  KSh {item.totalAmount.toLocaleString()}
                </span>
              </div>
            ))}
            
            <Separator />
            
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Subtotal</span>
                <span>KSh {total.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Delivery Fee</span>
                <span>KSh {deliveryFee.toLocaleString()}</span>
              </div>
              <Separator className="my-2" />
              <div className="flex justify-between text-lg font-bold">
                <span>Total Amount</span>
                <span className="text-primary">KSh {grandTotal.toLocaleString()}</span>
              </div>
            </div>
          </div>
        </Card>

        {/* Payment Method */}
        {paymentStatus === 'idle' && (
          <>
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <CreditCard className="h-5 w-5 text-primary" />
                <h3 className="font-semibold">Payment Method</h3>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center gap-3 p-3 border rounded-lg bg-primary/5 border-primary">
                  <Phone className="h-5 w-5 text-primary" />
                  <div>
                    <span className="font-medium">M-Pesa</span>
                    <p className="text-sm text-muted-foreground">
                      Pay securely with M-Pesa
                    </p>
                  </div>
                </div>
              </div>
            </Card>

            {/* Payment Form */}
            <Card className="p-4">
              <form onSubmit={handlePayment} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="phone">M-Pesa Phone Number</Label>
                  <Input
                    id="phone"
                    type="tel"
                    placeholder="0712345678"
                    value={phoneNumber}
                    onChange={(e) => setPhoneNumber(e.target.value)}
                    maxLength={10}
                    required
                    disabled={isProcessing}
                  />
                  <p className="text-xs text-muted-foreground">
                    Enter the phone number registered with M-Pesa
                  </p>
                  {phoneNumber && !validatePhoneNumber(phoneNumber) && (
                    <p className="text-xs text-destructive">
                      Please enter a valid Kenyan phone number
                    </p>
                  )}
                </div>

                <Button 
                  type="submit"
                  className="w-full bg-secondary hover:bg-secondary/90"
                  size="lg"
                  disabled={isProcessing || !validatePhoneNumber(phoneNumber) || !orderId}
                >
                  {isProcessing ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Initiating Payment...
                    </>
                  ) : (
                    `Pay KSh ${grandTotal.toLocaleString()}`
                  )}
                </Button>
              </form>
            </Card>
          </>
        )}

        {/* Security Notice */}
        <Card className="p-4 bg-muted/50">
          <div className="flex items-start gap-2">
            <Shield className="h-4 w-4 text-green-600 mt-0.5" />
            <div>
              <p className="text-xs text-muted-foreground">
                <strong>Secure Payment:</strong> Your payment is encrypted and secure. 
                We use M-Pesa's secure payment gateway. No card details are stored on our servers.
              </p>
            </div>
          </div>
        </Card>

        {/* Help Text */}
        <Card className="p-4 bg-blue-50 border-blue-200">
          <h4 className="font-semibold text-blue-900 mb-2">How to complete payment:</h4>
          <ol className="text-sm text-blue-700 space-y-1 list-decimal list-inside">
            <li>Enter your M-Pesa registered phone number</li>
            <li>Click "Pay" to receive an M-Pesa prompt</li>
            <li>Enter your M-Pesa PIN when prompted on your phone</li>
            <li>Wait for confirmation (automatic)</li>
          </ol>
        </Card>
      </div>

      <BottomNav />
    </div>
  );
};

export default Payment;