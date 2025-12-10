import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Mail, Lock, ChevronRight } from "lucide-react";
import { motion } from "framer-motion";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

const Login = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  
  const [formData, setFormData] = useState({
    email: "",
    password: ""
  });
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.email || !formData.password) {
      toast.error("Please fill in all fields");
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      toast.error("Please enter a valid email address");
      return;
    }

    setIsLoading(true);

    try {
      // Pass email and password to login function
      const result = await login(formData.email, formData.password);
      
      if (result.success) {
        toast.success("Login successful!");
        navigate("/dashboard");
      } else {
        // Handle specific error cases from backend
        if (result.error?.email) {
          toast.error(result.error.email[0]);
        } else if (result.error?.password) {
          toast.error(result.error.password[0]);
        } else if (result.error?.detail) {
          // Check for email verification errors
          if (result.error.detail.includes("Email not verified") || 
              result.error.detail.includes("email_verified")) {
            toast.error("Email not verified. Please check your email for verification instructions.");
            navigate("/verify-email", { 
              state: { 
                email: formData.email,
                message: "Please verify your email before logging in." 
              } 
            });
          } else if (result.error.detail.includes("Account is inactive")) {
            toast.error("Account is inactive. Please contact support.");
          } else if (result.error.detail.includes("Account is temporarily locked")) {
            toast.error("Account is temporarily locked due to too many failed attempts. Please try again later.");
          } else {
            toast.error(result.error.detail);
          }
        } else if (result.error?.non_field_errors) {
          // Django REST framework often uses non_field_errors
          toast.error(result.error.non_field_errors[0]);
        } else {
          toast.error(result.error?.message || "Login failed. Please try again.");
        }
      }
    } catch (error) {
      console.error("Login error:", error);
      toast.error("An unexpected error occurred. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleDemoLogin = async () => {
    // Optional: Demo login for testing
    setFormData({
      email: "demo@example.com",
      password: "demo123"
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
            <CardTitle className="text-2xl">Welcome back</CardTitle>
            <CardDescription>
              Enter your email to access your account
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
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
                    autoComplete="email"
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  Enter your registered email address
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="password">Password</Label>
                  <Link 
                    to="/forgot-password" 
                    className="text-xs text-secondary hover:underline"
                  >
                    Forgot password?
                  </Link>
                </div>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={handleChange}
                    className="pl-10"
                    required
                    autoComplete="current-password"
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
                    Logging in...
                  </>
                ) : (
                  <>
                    Login
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </>
                )}
              </Button>

              {/* Optional: Demo login button for testing */}
              {process.env.NODE_ENV === 'development' && (
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={handleDemoLogin}
                  size="sm"
                >
                  Fill Demo Credentials
                </Button>
              )}
            </form>

            {/* Login Help Information */}
            <div className="mt-6 p-4 bg-muted/30 rounded-lg border">
              <h4 className="text-sm font-semibold mb-2 text-center">Login Help</h4>
              <div className="text-xs text-muted-foreground space-y-1">
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>Use your email address to login (not phone number)</span>
                </p>
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>Ensure your email is verified before logging in</span>
                </p>
                <p className="flex items-start">
                  <span className="mr-1">•</span>
                  <span>Contact support if you can't access your account</span>
                </p>
              </div>
            </div>
          </CardContent>
          
          <div className="px-6 pb-6">
            <div className="text-center text-sm mb-4">
              <span className="text-muted-foreground">Don't have an account? </span>
              <Link to="/register" className="text-secondary hover:underline font-semibold">
                Register
              </Link>
            </div>
            
            <div className="text-center text-xs text-muted-foreground">
              <p>By logging in, you agree to our Terms of Service and Privacy Policy</p>
            </div>
          </div>
        </Card>
      </motion.div>
    </div>
  );
};

export default Login;