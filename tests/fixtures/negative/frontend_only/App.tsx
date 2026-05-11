import React from "react";

type User = {
  role: "guest" | "admin";
};

export function AdminButton({ user }: { user: User }) {
  if (user.role !== "admin") {
    return null;
  }

  return <button data-testid="admin-action">Disable account</button>;
}
