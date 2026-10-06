import { useNavigate } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login } from "@/lib/auth";

const Login = () => {
  const navigate = useNavigate();
  return (
    <Layout>
      <section className="min-h-[80vh] flex items-center justify-center py-20">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            login();
            navigate("/dashboard");
          }}
          className="w-full max-w-sm space-y-6 px-6"
        >
          <div className="text-center mb-8">
            <h1 className="font-serif text-4xl text-foreground mb-2">Welcome Home</h1>
            <p className="text-muted-foreground">Sign in to manage your devices</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" placeholder="you@example.com" className="rounded-none" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" placeholder="••••••••" className="rounded-none" />
          </div>
          <Button type="submit" size="lg" className="w-full rounded-none py-6 text-sm tracking-[0.15em] uppercase btn-premium">
            Login
          </Button>
        </form>
      </section>
    </Layout>
  );
};

export default Login;
