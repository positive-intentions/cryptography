import React from "react";
import { createRoot } from "react-dom/client";
import Cryptography from "./stories/components/Cryptography.tsx";

const App = () => {
  return (
    <div>
      <Cryptography>positive-intentions</Cryptography>
    </div>
  );
};

const container = document.getElementById("app");
const root = createRoot(container); // createRoot(container!) if you use TypeScript
root.render(<App />);
