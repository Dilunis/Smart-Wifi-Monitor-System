import { render, screen } from "@testing-library/react";
import App from "./App";

test("renders login gateway", () => {
  render(<App />);
  expect(screen.getByText(/Smart WiFi Monitor/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /authenticate/i })).toBeInTheDocument();
});
