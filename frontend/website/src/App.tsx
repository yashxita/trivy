import { useCallback, useEffect, useState } from "react";
import { Background, Logo, MoonIcon, SunIcon } from "./components/Bits";
import Landing from "./pages/Landing";
import TestPage from "./pages/TestPage";

type Theme = "dark" | "light";
type Route = "home" | "test";

function readRoute(): Route {
  return window.location.hash.startsWith("#/test") ? "test" : "home";
}

function systemTheme(): Theme {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export default function App() {
  const [route, setRoute] = useState<Route>(readRoute);
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("trivy-theme");
    return stored === "dark" || stored === "light" ? stored : systemTheme();
  });
  const [target, setTarget] = useState("");
  const [alert, setAlert] = useState(false);
  const onAlert = useCallback((v: boolean) => setAlert(v), []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    const onHash = () => {
      setRoute(readRoute());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  function go(next: Route) {
    window.location.hash = next === "test" ? "#/test" : "#/";
  }

  function toggleTheme() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("trivy-theme", next);
  }

  function scrollTo(id: string) {
    if (route !== "home") {
      go("home");
      window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" }), 60);
    } else {
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    }
  }

  return (
    <div className="site">
      <Background alert={route === "test" && alert} />
      <div className="wrap">
        <nav className="nav" aria-label="Main">
          <button type="button" className="brand" onClick={() => go("home")}>
            <Logo size={34} />
            Trivy
          </button>
          <div className="pill-nav">
            <button type="button" className={route === "home" ? "on" : ""} onClick={() => go("home")}>
              Home
            </button>
            <button type="button" onClick={() => scrollTo("checks")}>
              What we check
            </button>
            <button type="button" onClick={() => scrollTo("learn")}>
              Learn
            </button>
            <button type="button" className={route === "test" ? "on" : ""} onClick={() => go("test")}>
              Test
            </button>
          </div>
          <div className="nav__right">
            <button
              type="button"
              className="icon-button"
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              onClick={toggleTheme}
            >
              {theme === "dark" ? <SunIcon /> : <MoonIcon />}
            </button>
            <button type="button" className="btn btn--small" onClick={() => go("test")}>
              Start testing
            </button>
          </div>
        </nav>

        {route === "home" && <Landing target={target} setTarget={setTarget} onStart={() => go("test")} />}
        <div hidden={route !== "test"}>
          <TestPage target={target} setTarget={setTarget} onBack={() => go("home")} onAlert={onAlert} />
        </div>

        <footer className="footer">Trivy · scan only systems you are allowed to test.</footer>
      </div>
    </div>
  );
}