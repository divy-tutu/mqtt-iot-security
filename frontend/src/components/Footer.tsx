import { Link } from "react-router-dom";
export const Footer = () => (
  <footer className="site-footer">
    <div className="container-full flex flex-wrap items-center justify-between gap-4">
      <Link to="/" className="font-serif text-2xl">HomePulse<span className="text-primary">.</span></Link>
      <p className="text-xs text-muted-foreground">Connected living. Security you can examine.</p>
      <p className="text-xs text-muted-foreground">Information Security Lab · 2026</p>
    </div>
  </footer>
);
