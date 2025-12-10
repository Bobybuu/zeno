import { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { CheckCircle2, Truck, Phone, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import BottomNav from "@/components/BottomNav";

const OrderConfirmation = () => {
  const navigate = useNavigate();
  const location = useLocation();
  
  const { orderItems, orderId, totalAmount } = location.state || {};

  useEffect(() => {
    if (!orderItems || !orderId) {
      navigate('/cart');
    }
  }, [orderItems, orderId, navigate]);

  if (!orderItems || !orderId) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <div className="p-4 space-y-6">
        {/* Success Header */}
        <div className="text-center py-8">
          <CheckCircle2 className="h-16 w-16 text-green-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-green-600 mb-2">Order Confirmed!</h1>
          <p className="text-muted-foreground">Thank you for your purchase</p>
          <p className="text-sm text-muted-foreground mt-1">Order #: {orderId}</p>
        </div>

        {/* Order Summary */}
        <Card className="p-4">
          <h3 className="font-semibold mb-3">Order Details</h3>
          <div className="space-y-3">
            {orderItems.map((item: any, index: number) => (
              <div key={index} className="flex justify-between items-start">
                <div>
                  <p className="font-medium">{item.productName}</p>
                  <p className="text-sm text-muted-foreground">
                    {item.vendorName} × {item.quantity}
                  </p>
                </div>
                <span className="font-semibold">
                  KSh {item.totalAmount.toLocaleString()}
                </span>
              </div>
            ))}
            <div className="flex justify-between font-bold pt-2 border-t">
              <span>Total</span>
              <span>KSh {totalAmount.toLocaleString()}</span>
            </div>
          </div>
        </Card>

        {/* Delivery Information */}
        <Card className="p-4">
          <h3 className="font-semibold mb-3">Delivery Information</h3>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <Truck className="h-5 w-5 text-primary" />
              <div>
                <p className="font-medium">Standard Delivery</p>
                <p className="text-sm text-muted-foreground">Estimated delivery: 1-2 hours</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <MapPin className="h-5 w-5 text-primary" />
              <div>
                <p className="font-medium">Delivery Address</p>
                <p className="text-sm text-muted-foreground">Nairobi, Kenya</p>
              </div>
            </div>
          </div>
        </Card>

        {/* Next Steps */}
        <Card className="p-4 bg-blue-50 border-blue-200">
          <h3 className="font-semibold text-blue-900 mb-2">What's Next?</h3>
          <ul className="text-sm text-blue-700 space-y-2 list-disc list-inside">
            <li>You will receive an SMS confirmation</li>
            <li>Our delivery team will contact you shortly</li>
            <li>Track your order in the Orders section</li>
          </ul>
        </Card>

        <div className="space-y-3">
          <Button 
            className="w-full" 
            onClick={() => navigate('/orders')}
          >
            View My Orders
          </Button>
          <Button 
            variant="outline" 
            className="w-full"
            onClick={() => navigate('/services/gas')}
          >
            Continue Shopping
          </Button>
        </div>
      </div>

      <BottomNav />
    </div>
  );
};

export default OrderConfirmation;