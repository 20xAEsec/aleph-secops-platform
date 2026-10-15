import { Suspense } from "react";
import DetectionsClient from "./DetectionsClient";

async function WithQuery({ searchParams }: { searchParams: PageProps<"/detections">["searchParams"] }) {
  const { q } = await searchParams;
  return <DetectionsClient initialDescription={typeof q === "string" ? q : ""} />;
}

export default function DetectionsPage({ searchParams }: PageProps<"/detections">) {
  return (
    <Suspense fallback={<DetectionsClient initialDescription="" />}>
      <WithQuery searchParams={searchParams} />
    </Suspense>
  );
}
