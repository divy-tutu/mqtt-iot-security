import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus } from "lucide-react";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { myDevices, Device } from "@/data/devices";
import { Plug } from "lucide-react";

const Dashboard = () => {
  const [devices, setDevices] = useState<Device[]>(myDevices);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [room, setRoom] = useState("");

  const addDevice = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setDevices([
      ...devices,
      {
        id: `${name.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`,
        name,
        room: room || "Unassigned",
        type: "Device",
        icon: Plug,
        image: "https://images.unsplash.com/photo-1558002038-1055907df827?w=800&q=80",
      },
    ]);
    setName("");
    setRoom("");
    setOpen(false);
  };

  return (
    <Layout>
      <section className="py-16 md:py-24">
        <div className="container-full">
          <div className="flex items-end justify-between mb-12 gap-4">
            <div>
              <p className="text-[11px] font-semibold tracking-[0.3em] uppercase text-primary mb-3">My Home</p>
              <h1 className="font-serif text-4xl md:text-5xl text-foreground">Your Devices</h1>
            </div>
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button className="rounded-none tracking-[0.15em] uppercase text-xs btn-premium">
                  <Plus className="w-4 h-4 mr-2" /> Add Device
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle className="font-serif text-2xl">Add a Device</DialogTitle>
                </DialogHeader>
                <form onSubmit={addDevice} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="dname">Device name</Label>
                    <Input id="dname" value={name} onChange={(e) => setName(e.target.value)} placeholder="Living Room Lamp" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="droom">Room</Label>
                    <Input id="droom" value={room} onChange={(e) => setRoom(e.target.value)} placeholder="Living Room" />
                  </div>
                  <Button type="submit" className="w-full rounded-none">Add</Button>
                </form>
              </DialogContent>
            </Dialog>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
            {devices.map((d) => (
              <Link key={d.id} to={`/device/${d.id}`} state={{ device: { ...d, icon: undefined } }} className="group block">
                <div className="aspect-[4/3] overflow-hidden mb-4">
                  <img src={d.image} alt={d.name} className="w-full h-full object-cover transition-transform duration-[1.5s] group-hover:scale-105" />
                </div>
                <h3 className="font-serif text-2xl text-foreground group-hover:text-primary transition-colors">{d.name}</h3>
                <p className="text-sm text-muted-foreground mt-1">{d.room}</p>
              </Link>
            ))}
          </div>
        </div>
      </section>
    </Layout>
  );
};

export default Dashboard;
