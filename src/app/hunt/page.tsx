import { Suspense } from "react";
import HuntClient from "./HuntClient";

async function WithQuery({ searchParams }: { searchParams: PageProps<"/hunt">["searchParams"] }) {
  const { q, case: caseId } = await searchParams;
  return <HuntClient initialHypothesis={typeof q === "string" ? q : ""} caseId={typeof caseId === "string" ? caseId : undefined} />;
}

export default function HuntPage({ searchParams }: PageProps<"/hunt">) {
  return (
    <Suspense fallback={<HuntClient initialHypothesis="" />}>
      <WithQuery searchParams={searchParams} />
    </Suspense>
  );
}
