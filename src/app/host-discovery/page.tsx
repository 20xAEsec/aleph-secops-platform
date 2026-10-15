import { Suspense } from "react";
import { EXAMPLE_MACS, RESOURCE_TYPES, isResourceType, type ResourceType } from "@/lib/secops/discovery";
import HostDiscoveryClient, { type TypeOption } from "./HostDiscoveryClient";

// Resource metadata is resolved here so the client bundle never pulls in the telemetry generator.
const OPTIONS: TypeOption[] = (Object.keys(RESOURCE_TYPES) as ResourceType[]).map((id) => ({
  id,
  ...RESOURCE_TYPES[id],
  examples: id === "mac" ? EXAMPLE_MACS : [...RESOURCE_TYPES[id].examples],
}));

async function WithQuery({ searchParams }: { searchParams: PageProps<"/host-discovery">["searchParams"] }) {
  const { type, q } = await searchParams;
  return <HostDiscoveryClient options={OPTIONS} initialType={isResourceType(type) ? type : "hostname"} initialValue={typeof q === "string" ? q : ""} />;
}

export default function HostDiscoveryPage({ searchParams }: PageProps<"/host-discovery">) {
  return (
    <Suspense fallback={<HostDiscoveryClient options={OPTIONS} initialType="hostname" initialValue="" />}>
      <WithQuery searchParams={searchParams} />
    </Suspense>
  );
}
