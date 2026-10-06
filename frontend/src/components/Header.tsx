import { Link, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { isLoggedIn, logout } from "@/lib/auth";

export const Header = () => {
  const [scrolled, setScrolled] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const loggedIn = isLoggedIn();

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header
      className={cn(
        "sticky top-0 z-50 transition-all duration-500",
        scrolled
          ? "bg-background/95 backdrop-blur-md border-b border-border shadow-sm"
          : "bg-background/80 backdrop-blur-sm border-b border-transparent"
      )}
    >
      <nav className="container-full">
        <div className="flex items-center justify-between h-16 md:h-20">
          <Link to="/" className="font-serif text-2xl md:text-3xl tracking-tight text-foreground hover:text-primary transition-colors">
            HomePulse
          </Link>
          <button
            onClick={() => {
              if (loggedIn) {
                logout();
                navigate("/");
              } else {
                navigate("/login");
              }
            }}
            className="text-xs font-medium tracking-[0.15em] uppercase text-muted-foreground hover:text-foreground transition-colors link-underline"
          >
            {loggedIn ? "Log Out" : "Login"}
          </button>
        </div>
      </nav>
    </header>
  );
};
