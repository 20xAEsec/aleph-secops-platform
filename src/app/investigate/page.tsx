import { Suspense } from "react";
import InvestigateClient from "./InvestigateClient";

async function WithQuery({ searchParams }: { searchParams: PageProps<"/investigate">["searchParams"] }) {
  const { q } = await searchParams;
  return <InvestigateClient initialIoc={typeof q === "string" ? q : ""} />;
}

export default function InvestigatePage({ searchParams }: PageProps<"/investigate">) {
  return (
    <Suspense fallback={<InvestigateClient initialIoc="" />}>
      <WithQuery searchParams={searchParams} />
    </Suspense>
  );
}
