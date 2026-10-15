import PageHeader from "@/components/PageHeader";
import { AS_OF, IOCS, TREND, breakdown, iocStats } from "@/lib/secops/iocInventory";
import IocOverviewClient from "./IocOverviewClient";

const KIND_LABEL: Record<string, string> = { ipv4: "IP address", domain: "Domain", url: "URL", sha256: "SHA-256", md5: "MD5", email: "Email" };

export default function IocOverviewPage() {
  const actors = breakdown((i) => i.actor.name, (i) => i.hits30d)
    .filter((a) => a.label !== "No attribution")
    .slice(0, 7)
    .map((a) => ({ ...a, sub: IOCS.find((i) => i.actor.name === a.label)!.actor.country }));
  const countries = breakdown((i) => i.actor.countryName.replace(" (assessed)", ""))
    .filter((c) => c.label !== "n/a")
    .map((c) => ({ ...c, sub: IOCS.find((i) => i.actor.countryName.startsWith(c.label))!.actor.country }));
  const kinds = breakdown((i) => i.kind).map((k) => ({ ...k, label: KIND_LABEL[k.label] }));

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader kicker="Threat Intelligence · IOC Overview" title="IOC Overview">
        The indicator repository as it exists in the SIEM: intel-synced IoCs with attribution, match volume and detection history.
        Indicators behind a currently open detection are pinned to the top of the inventory.
      </PageHeader>
      <IocOverviewClient iocs={IOCS} trend={TREND} stats={iocStats()} actors={actors} countries={countries} kinds={kinds} asOf={AS_OF} />
    </div>
  );
}
