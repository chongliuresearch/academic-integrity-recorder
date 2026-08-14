import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import "./extra.css";
import "./workspace.css";
import "./privacy.css";

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
