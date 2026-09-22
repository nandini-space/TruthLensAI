import { redirect } from "next/navigation";

/** Keep the root URL useful instead of rendering a blank application shell. */
export default function HomePage() {
  redirect("/investigations");
}
