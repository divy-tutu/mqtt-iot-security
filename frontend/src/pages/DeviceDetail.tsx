import { Link, useLocation, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Layout } from "@/components/Layout";
import { myDevices } from "@/data/devices";

const DeviceDetail = () => {
  const { id } = useParams();
  const location = useLocation();
  const device = myDevices.find((d) => d.id === id) ?? (location.state as any)?.device;

  return (
    <Layout>
      <section className="py-16 md:py-24">
        <div className="container-full max-w-4xl">
          <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-10">
            <ArrowLeft className="w-4 h-4" /> Back to devices
          </Link>
          {device ? (
            <>
              <div className="aspect-[16/9] overflow-hidden mb-8">
                <img src={device.image} alt={device.name} className="w-full h-full object-cover" />
              </div>
              <p className="text-[11px] font-semibold tracking-[0.3em] uppercase text-primary mb-3">{device.room}</p>
              <h1 className="font-serif text-4xl md:text-5xl text-foreground mb-8">{device.name}</h1>
              <div className="border border-dashed border-border p-12 text-center text-muted-foreground">
                Device details coming soon.
              </div>
            </>
          ) : (
            <p className="text-muted-foreground">Device not found.</p>
          )}
        </div>
      </section>
    </Layout>
  );
};

export default DeviceDetail;
