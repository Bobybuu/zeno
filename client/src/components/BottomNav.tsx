import { useNavigate, useLocation } from "react-router-dom";
import { Home, MapPin, ShoppingCart, User } from "lucide-react";
import { cn } from "@/lib/utils";

const BottomNav = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { icon: Home, label: "Home", path: "/dashboard" },
    { icon: MapPin, label: "Roadside Services", path: "/services/roadside" },
    { icon: ShoppingCart, label: "Cart", path: "/cart" },
    { icon: User, label: "Account", path: "/account" },
  ];

  return (
    <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-border z-50">
      <div className="flex justify-around items-center py-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          
          return (
            <button
              key={item.path}
              onClick={() => navigate(item.path)}
              className="flex flex-col items-center justify-center p-2 min-w-[64px]"
            >
              <Icon 
                className={cn(
                  "h-5 w-5 mb-1 transition-colors",
                  isActive ? "text-secondary" : "text-muted-foreground"
                )}
              />
              <span 
                className={cn(
                  "text-xs transition-colors",
                  isActive ? "text-secondary font-medium" : "text-muted-foreground"
                )}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default BottomNav;