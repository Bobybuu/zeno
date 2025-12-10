import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Mail, Phone, Lock, User, ChevronRight } from "lucide-react";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

const Register = () => {
  const navigate = useNavigate();
  const { register } = useAuth();
  
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phoneNumber: "",
    password: "",
    confirmPassword: "",
    userType: "customer"
  });

  const [isLoading, setIsLoading] = useState(false);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      toast.error("Please enter a valid email address");
      return;
    }

    // Phone number validation (still required but not for OTP)
    const phoneRegex = /^\+?[\d\s-()]{10,}$/;
    if (!phoneRegex.test(formData.phoneNumber)) {
      toast.error("Please enter a valid phone number with country code");
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      toast.error("Passwords don't match");
      return;
    }

    if (formData.password.length < 6) {
      toast.error("Password must be at least 6 characters long");
      return;
    }

    setIsLoading(true);

    try {
      const registrationData = {
        // Email is now primary identifier
        email: formData.email.toLowerCase().trim(),
        password: formData.password,
        password_confirm: formData.confirmPassword,
        user_type: formData.userType,
        phone_number: formData.phoneNumber,
        location: "",
        first_name: formData.firstName,
        last_name: formData.lastName
      };

      const result = await register(registrationData);
      
      if (result.success) {
        toast.success("Registration successful! Please check your email for verification.");
        // Don't navigate to dashboard yet - user needs to verify email
        // Show verification message instead
        navigate("/check-email", { 
          state: { 
            email: formData.email,
            message: "Please check your email for verification instructions before logging in." 
          } 
        });
      } else {
        // Handle specific error cases from backend
        if (result.error?.email) {
          toast.error(result.error.email[0]);
        } else if (result.error?.password) {
          toast.error(result.error.password[0]);
        } else if (result.error?.phone_number) {
          toast.error(result.error.phone_number[0]);
        } else if (result.error?.detail) {
          toast.error(result.error.detail);
        } else {
          toast.error(result.error?.message || "Registration failed");
        }
      }
    } catch (error) {
      console.error("Registration error:", error);
      toast.error("An unexpected error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background to-muted flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <Card className="border-0 shadow-xl">
          <CardHeader className="space-y-1 text-center">
            <div className="mb-4">
              <h1 className="text-4xl font-bold text-primary">ZENO</h1>
              <p className="text-sm text-muted-foreground">Services You Can Count On</p>
            </div>
            <CardTitle className="text-2xl">Create Account</CardTitle>
            <CardDescription>
              Join thousands of users trusting ZENO services
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleRegister} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First Name</Label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="firstName"
                      name="firstName"
                      placeholder="John"
                      value={formData.firstName}
                      onChange={handleChange}
                      className="pl-10"
                      required
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    name="lastName"
                    placeholder="Doe"
                    value={formData.lastName}
                    onChange={handleChange}
                    required
                  />
                </div>
              </div>

              {/* Email Field - PRIMARY IDENTIFIER */}
              <div className="space-y-2">
                <Label htmlFor="email">Email Address</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="your.email@example.com"
                    value={formData.email}
                    onChange={handleChange}
                    className="pl-10"
                    required
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  This will be your login ID. We'll send verification to this email.
                </p>
              </div>

              {/* Phone Number - REQUIRED BUT NOT FOR OTP */}
              <div className="space-y-2">
                <Label htmlFor="phoneNumber">Phone Number</Label>
                <div className="relative">
                  <Phone className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="phoneNumber"
                    name="phoneNumber"
                    type="tel"
                    placeholder="+254712345678"
                    value={formData.phoneNumber}
                    onChange={handleChange}
                    className="pl-10"
                    required
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  Include country code. Required for service notifications.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="userType">Account Type</Label>
                <select
                  id="userType"
                  name="userType"
                  value={formData.userType}
                  onChange={handleChange}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-secondary text-gray-900"
                >
                  <option value="customer">Customer</option>
                  <option value="vendor">Service Vendor</option>
                  <option value="mechanic">Mechanic</option>
                </select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Create password (min. 6 characters)"
                    value={formData.password}
                    onChange={handleChange}
                    className="pl-10"
                    required
                    minLength={6}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    placeholder="Confirm your password"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    className="pl-10"
                    required
                    minLength={6}
                  />
                </div>
              </div>

              <Button 
                type="submit" 
                className="w-full bg-secondary hover:bg-secondary/90 text-white font-semibold"
                size="lg"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Creating Account...
                  </>
                ) : (
                  <>
                    Create Account
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </>
                )}
              </Button>
            </form>

            {/* Email Verification Info */}
            <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
              <h4 className="text-sm font-semibold mb-2 text-center text-blue-800">
                Email Verification Required
              </h4>
              <div className="text-xs text-blue-700 space-y-1">
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>You'll receive a verification email after registration</span>
                </p>
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>Check your inbox (and spam folder) for the verification link</span>
                </p>
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>You must verify your email before logging in</span>
                </p>
              </div>
            </div>
          </CardContent>
          <div className="px-6 pb-6">
            <div className="text-center text-sm mb-4">
              <span className="text-muted-foreground">Already have an account? </span>
              <Link to="/login" className="text-secondary hover:underline font-semibold">
                Login
              </Link>
            </div>
            <div className="text-center text-xs text-muted-foreground">
              By creating an account, you agree to our Terms of Service and Privacy Policy
            </div>
          </div>
        </Card>
      </motion.div>
    </div>
  );
};

export default Register;