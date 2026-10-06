import { Refrigerator, Lightbulb, Thermometer, Camera, Lock, Speaker, Plug, Wind, LucideIcon } from "lucide-react";
import securityCameraImage from "@/assets/security-camera.jpg";
import thermostatImage from "@/assets/thermostat.jpg";

export interface Device {
  id: string;
  name: string;
  room: string;
  type: string;
  icon: LucideIcon;
  image: string;
}

export const myDevices: Device[] = [
  {
    id: "fridge",
    name: "Fridge",
    room: "Kitchen",
    type: "Appliance",
    icon: Refrigerator,
    image: "https://images.unsplash.com/photo-1571175443880-49e1d25b2bc5?w=800&q=80",
  },
  {
    id: "master-bedroom-lights",
    name: "Master Bedroom Lights",
    room: "Master Bedroom",
    type: "Lighting",
    icon: Lightbulb,
    image: "https://images.unsplash.com/photo-1616594039964-ae9021a400a0?w=800&q=80",
  },
];

export interface Appliance {
  name: string;
  description: string;
  icon: LucideIcon;
  image: string;
}

export const availableAppliances: Appliance[] = [
  { name: "Smart Thermostat", description: "Keep every room at the perfect temperature.", icon: Thermometer, image: thermostatImage },
  { name: "Security Camera", description: "See what's happening at home from anywhere.", icon: Camera, image: securityCameraImage },
  { name: "Smart Lock", description: "Lock and unlock your doors with a tap.", icon: Lock, image: "https://images.unsplash.com/photo-1558002038-1055907df827?w=800&q=80" },
  { name: "Smart Speaker", description: "Music and voice control in every room.", icon: Speaker, image: "https://images.unsplash.com/photo-1543512214-318c7553f230?w=800&q=80" },
  { name: "Smart Plug", description: "Turn any outlet into a smart outlet.", icon: Plug, image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=800&q=80" },
  { name: "Air Purifier", description: "Cleaner air, monitored automatically.", icon: Wind, image: "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?w=800&q=80" },
];
