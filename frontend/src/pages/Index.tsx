import { Link } from "react-router-dom";
import { motion, useScroll, useTransform } from "framer-motion";
import { ArrowRight, ArrowDown } from "lucide-react";
import { useRef } from "react";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { availableAppliances } from "@/data/devices";

const Index = () => {
  const heroRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: heroRef, offset: ["start start", "end start"] });
  const heroImageY = useTransform(scrollYProgress, [0, 1], ["0%", "20%"]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.8], [1, 0]);

  return (
    <Layout>
      <section ref={heroRef} className="relative h-[100svh] -mt-16 md:-mt-20 overflow-hidden">
        <motion.div className="absolute inset-0" style={{ y: heroImageY }}>
          <img
            src="https://images.unsplash.com/photo-1618221195710-dd6b41faaea6?w=1920&q=80"
            alt="Smart home living room"
            className="w-full h-[120%] object-cover animate-ken-burns"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-charcoal/30 via-charcoal/10 to-charcoal/50" />
        </motion.div>

        <motion.div
          className="relative container-full h-full flex flex-col justify-end pb-20 md:pb-28 pt-16 md:pt-20"
          style={{ opacity: heroOpacity }}
        >
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, delay: 0.3 }}
            className="max-w-3xl"
          >
            <p className="text-[11px] font-semibold tracking-[0.3em] uppercase text-white/70 mb-6">
              Your Smart Home
            </p>
            <h1 className="font-serif text-5xl md:text-7xl lg:text-8xl xl:text-9xl text-white mb-8 leading-[0.9] tracking-tight">
              A Home That
              <br />
              <span className="italic font-normal">Listens</span>
            </h1>
            <p className="text-base md:text-lg text-white/80 mb-10 leading-relaxed max-w-lg">
              Your devices, your space, your peace of mind. Stay connected to home from one calm, simple place.
            </p>
            <Button asChild size="lg" className="rounded-none px-10 py-6 text-sm tracking-[0.15em] uppercase btn-premium">
              <Link to="/dashboard">
                Enter Your Home
                <ArrowRight className="ml-3 w-4 h-4" />
              </Link>
            </Button>
            <Link to="/lab" className="inline-flex items-center gap-2 text-white/90 text-sm ml-0 sm:ml-7 mt-5 sm:mt-0 hover:text-white transition-colors">Explore the security lab <ArrowRight size={16} /></Link>
          </motion.div>

          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2">
            <span className="text-[10px] tracking-[0.3em] uppercase text-white/50">Scroll</span>
            <motion.div animate={{ y: [0, 8, 0] }} transition={{ duration: 2, repeat: Infinity }}>
              <ArrowDown className="w-4 h-4 text-white/50" />
            </motion.div>
          </div>
        </motion.div>
      </section>

      <section className="py-20 md:py-28">
        <div className="container-full">
          <p className="text-[11px] font-semibold tracking-[0.3em] uppercase text-primary mb-3">Expand Your Home</p>
          <h2 className="font-serif text-4xl md:text-5xl text-foreground mb-14">Smart Appliances You Can Add</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
            {availableAppliances.map((a, i) => (
              <motion.div
                key={a.name}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: i * 0.08 }}
                className="group"
              >
                <div className="aspect-[4/3] overflow-hidden mb-5">
                  <img src={a.image} alt={a.name} className="w-full h-full object-cover transition-transform duration-1000 group-hover:scale-105" />
                </div>
                <h3 className="font-serif text-2xl text-foreground mb-2">{a.name}</h3>
                <p className="text-muted-foreground">{a.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </Layout>
  );
};

export default Index;
