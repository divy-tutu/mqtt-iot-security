import { Link, NavLink } from "react-router-dom";
import { Activity, ArrowUpRight } from "lucide-react";

export const Header = () => (
  <header className="site-header">
    <nav className="container-full site-navigation" aria-label="Main navigation">
      <Link to="/" className="site-brand" aria-label="HomePulse home">
        <Activity size={21} strokeWidth={1.5} aria-hidden="true" />HomePulse<span className="brand-dot">.</span>
      </Link>
      <div className="site-links">
        <NavLink to="/" end>Home</NavLink>
        <NavLink to="/dashboard">My Home</NavLink>
        <NavLink to="/lab" className="lab-nav">Security Lab <ArrowUpRight size={14} aria-hidden="true" /></NavLink>
      </div>
    </nav>
  </header>
);
