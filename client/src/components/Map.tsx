import { useEffect, useRef, useState } from "react";
import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";

interface Provider {
  id: number;
  name: string;
  location: string;
  coords: [number, number];
  price: string;
  rating?: number;
  distance?: string;
}

interface MapProps {
  providers?: Provider[];
  center?: [number, number];
  userLocation?: [number, number] | null;
  zoom?: number;
}

interface MapboxConfig {
  accessToken: string;
  styleUrl: string;
}

const Map = ({
  providers = [],
  center = [36.817223, -1.286389], // ✅ FIXED: [lng, lat] format (Nairobi)
  userLocation = null,
  zoom = 13,
}: MapProps) => {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapRef = useRef<mapboxgl.Map | null>(null);
  const markersRef = useRef<mapboxgl.Marker[]>([]);
  const [mapLoaded, setMapLoaded] = useState(false);
  const [mapError, setMapError] = useState<string | null>(null);
  const [mapboxConfig, setMapboxConfig] = useState<MapboxConfig | null>(null);

  // Fetch Mapbox configuration from backend
  useEffect(() => {
    const fetchMapboxConfig = async () => {
      try {
        const response = await fetch('https://api.zenoservices.co.ke/api/services/mapbox-config/');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const config: MapboxConfig = await response.json();
        setMapboxConfig(config);
        
        // Set Mapbox token globally
        mapboxgl.accessToken = config.accessToken;
      } catch (error) {
        console.error('Failed to fetch Mapbox config:', error);
        setMapError('Failed to load map configuration');
        
        // Fallback to environment variable if available
        const fallbackToken = import.meta.env.VITE_MAPBOX_ACCESS_TOKEN || process.env.REACT_APP_MAPBOX_ACCESS_TOKEN;
        if (fallbackToken) {
          mapboxgl.accessToken = fallbackToken;
          setMapboxConfig({
            accessToken: fallbackToken,
            styleUrl: import.meta.env.VITE_MAPBOX_STYLE_URL || process.env.REACT_APP_MAPBOX_STYLE_URL || 'mapbox://styles/mapbox/streets-v12'
          });
        }
      }
    };

    fetchMapboxConfig();
  }, []);

  // Clear all markers
  const clearMarkers = () => {
    markersRef.current.forEach(marker => marker.remove());
    markersRef.current = [];
  };

  // Add provider markers
  const addProviderMarkers = (map: mapboxgl.Map) => {
    providers.forEach((provider) => {
      // Validate coordinates
      if (!provider.coords || 
          isNaN(provider.coords[0]) || isNaN(provider.coords[1]) ||
          Math.abs(provider.coords[0]) > 180 || Math.abs(provider.coords[1]) > 90) {
        console.warn('Invalid coordinates for provider:', provider.id, provider.coords);
        return;
      }

      try {
        // Create custom marker element
        const el = document.createElement('div');
        el.className = 'custom-marker';
        el.innerHTML = `
          <div class="w-6 h-6 bg-red-500 rounded-full border-2 border-white shadow-lg flex items-center justify-center">
            <span class="text-white text-xs font-bold">🔥</span>
          </div>
        `;

        const marker = new mapboxgl.Marker({
          element: el,
          anchor: 'bottom'
        })
          .setLngLat(provider.coords)
          .setPopup(
            new mapboxgl.Popup({ offset: 25 })
              .setHTML(`
                <div class="p-2 max-w-xs">
                  <h3 class="font-semibold text-sm">${provider.name}</h3>
                  <p class="text-xs text-gray-600 mt-1">${provider.location}</p>
                  ${provider.price ? `<p class="text-sm font-semibold text-green-600 mt-1">${provider.price}</p>` : ''}
                  ${provider.rating ? `<p class="text-xs text-yellow-600 mt-1">⭐ ${provider.rating}</p>` : ''}
                  ${provider.distance ? `<p class="text-xs text-gray-500 mt-1">${provider.distance} away</p>` : ''}
                </div>
              `)
          )
          .addTo(map);

        markersRef.current.push(marker);
      } catch (error) {
        console.error('Error adding marker for provider:', provider.id, error);
      }
    });
  };

  // Add user location marker
  const addUserMarker = (map: mapboxgl.Map, coords: [number, number]) => {
    try {
      const el = document.createElement('div');
      el.className = 'user-marker';
      el.innerHTML = `
        <div class="w-8 h-8 bg-blue-500 rounded-full border-2 border-white shadow-lg flex items-center justify-center">
          <span class="text-white text-xs">📍</span>
        </div>
      `;

      const marker = new mapboxgl.Marker({
        element: el,
        anchor: 'bottom'
      })
        .setLngLat(coords)
        .setPopup(new mapboxgl.Popup({ offset: 25 }).setText('Your location'))
        .addTo(map);

      markersRef.current.push(marker);
    } catch (error) {
      console.error('Error adding user marker:', error);
    }
  };

  // Initialize map only when config is available
  useEffect(() => {
    if (!mapContainer.current || !mapboxConfig) return;

    // Check if Mapbox token is available
    if (!mapboxgl.accessToken || mapboxgl.accessToken === 'your-mapbox-token-here') {
      setMapError('Mapbox access token not configured');
      return;
    }

    try {
      const map = new mapboxgl.Map({
        container: mapContainer.current,
        style: mapboxConfig.styleUrl,
        center: center,
        zoom: zoom,
        pitch: 0,
        bearing: 0,
        antialias: false,
      });

      mapRef.current = map;

      // Add navigation controls
      map.addControl(new mapboxgl.NavigationControl(), "top-right");

      // Handle map load
      map.on('load', () => {
        setMapLoaded(true);
        setMapError(null);
        
        // Add markers after map is loaded
        addProviderMarkers(map);

        // Handle user location
        if (userLocation) {
          addUserMarker(map, userLocation);
          map.flyTo({ center: userLocation, zoom: 14 });
        } else {
          if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
              (position) => {
                const { latitude, longitude } = position.coords;
                const userCoords: [number, number] = [longitude, latitude];
                addUserMarker(map, userCoords);
                map.flyTo({ center: userCoords, zoom: 14 });
              },
              (error) => {
                console.warn("Geolocation failed:", error);
              },
              { 
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 300000
              }
            );
          }
        }
      });

      // Handle map errors
      map.on('error', (e) => {
        console.error('Map error:', e);
        setMapError('Failed to load map. Please check your Mapbox configuration.');
      });

      // Cleanup function
      return () => {
        if (mapRef.current) {
          clearMarkers();
          mapRef.current.remove();
          mapRef.current = null;
        }
      };

    } catch (error) {
      console.error("Map initialization error:", error);
      setMapError('Failed to initialize map');
    }
  }, [mapboxConfig]); // Initialize map when config is available

  // Update markers when providers change
  useEffect(() => {
    if (mapRef.current && mapLoaded) {
      clearMarkers();
      addProviderMarkers(mapRef.current);
    }
  }, [providers, mapLoaded]);

  // Update user location
  useEffect(() => {
    if (mapRef.current && mapLoaded && userLocation) {
      const userMarkers = markersRef.current.filter(marker => 
        marker.getElement().classList.contains('user-marker')
      );
      userMarkers.forEach(marker => {
        marker.remove();
        markersRef.current = markersRef.current.filter(m => m !== marker);
      });

      addUserMarker(mapRef.current, userLocation);
      mapRef.current.flyTo({ center: userLocation, zoom: 14 });
    }
  }, [userLocation, mapLoaded]);

  // Show loading state while fetching config
  if (!mapboxConfig && !mapError) {
    return (
      <div className="relative w-full h-full rounded-lg overflow-hidden border bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-2"></div>
          <p className="text-sm text-gray-600">Loading map configuration...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative w-full h-full rounded-lg overflow-hidden border">
      <div 
        ref={mapContainer} 
        className="absolute inset-0"
        style={{ minHeight: '400px' }}
      />
      
      {/* Loading overlay */}
      {!mapLoaded && !mapError && (
        <div className="absolute inset-0 bg-gray-100 flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-2"></div>
            <p className="text-sm text-gray-600">Loading map...</p>
          </div>
        </div>
      )}

      {/* Error overlay */}
      {mapError && (
        <div className="absolute inset-0 bg-red-50 flex items-center justify-center">
          <div className="text-center">
            <div className="text-red-500 text-lg mb-2">⚠️</div>
            <p className="text-sm text-red-700">{mapError}</p>
            <button 
              onClick={() => window.location.reload()}
              className="mt-2 px-4 py-2 bg-red-500 text-white rounded text-sm hover:bg-red-600"
            >
              Retry
            </button>
          </div>
        </div>
      )}

      {/* Map attribution */}
      {mapLoaded && (
        <div className="absolute bottom-2 left-2 text-xs text-gray-500 bg-white/80 px-2 py-1 rounded">
          © Mapbox © OpenStreetMap
        </div>
      )}
    </div>
  );
};

export default Map;