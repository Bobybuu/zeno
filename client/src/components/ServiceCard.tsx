import { Card } from "@/components/ui/card";
import { ChevronRight } from "lucide-react";

interface ServiceCardProps {
  title: string;
  description: string;
  icon: string;
  color: string;
  onClick?: () => void;
}

const ServiceCard = ({ title, description, icon, color, onClick }: ServiceCardProps) => {
  return (
    <Card 
      className="service-card cursor-pointer overflow-hidden group"
      onClick={onClick}
    >
      <div className={`h-2 ${color}`} />
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="text-4xl mb-3">{icon}</div>
            <h3 className="text-lg font-semibold mb-1">{title}</h3>
            <p className="text-sm text-muted-foreground">{description}</p>
          </div>
          <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-primary transition-colors mt-1" />
        </div>
      </div>
    </Card>
  );
};

export default ServiceCard;