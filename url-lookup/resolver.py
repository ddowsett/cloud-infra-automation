"""
Core resolver: URL -> infrastructure location.

Chain:
  1. Resolve the hostname via DNS (live) to IP address(es).
  2. Look up the Route 53 record for the hostname to capture alias targets
     (API Gateway / CloudFront / ELB aliases name the resource directly, which
     is more precise than IP attribution).
  3. For each resolved private IP, query the AWS Config org aggregator
     ('us-regions') for the owning ENI -> accountId, region, resourceId, and the
     ENI description (which reveals the service + workload).
  4. Classify the resource type from the ENI description / interface type.

Credentials: uses the default boto3 credential chain. On the EC2 instance this
is the instance profile. For local testing, pass an AWS profile name as the
last CLI arg.

Read-only: performs only DNS lookups and Config/Route53 describe/select calls.
"""

from __future__ import annotations

import ipaddress
import socket
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

import boto3


import os

# Config aggregator covering the org across US regions (us-east-1/2, us-west-1/2).
DEFAULT_AGGREGATOR = os.environ.get("RESOLVER_AGGREGATOR", "us-regions")
AGGREGATOR_REGION = os.environ.get("RESOLVER_AGGREGATOR_REGION", "us-west-2")
# Cross-account read role deployed to every account via StackSet. Overridable at
# deploy time. No ExternalId -- trust is scoped to the CloudInfraEc2Role principal.
ASSUME_ROLE_NAME = os.environ.get("RESOLVER_ASSUME_ROLE", "CsaaInfraResolverReadRole")


@dataclass
class ResourceMatch:
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_id: Optional[str] = None
    private_ip: Optional[str] = None
    description: Optional[str] = None
    interface_type: Optional[str] = None
    resource_type: Optional[str] = None
    workload_hint: Optional[str] = None


@dataclass
class ZoneRecord:
    """A record found for the hostname in a specific (account, zone)."""
    zone_account_id: Optional[str] = None
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    record_type: Optional[str] = None
    alias_target: Optional[str] = None
    values: list = field(default_factory=list)   # non-alias record values (A/CNAME)


@dataclass
class ResolveResult:
    url: str = ""
    hostname: str = ""
    resolved_ips: list = field(default_factory=list)
    dns_error: Optional[str] = None
    candidate_zones: list = field(default_factory=list)   # zones (across accounts) whose name suffixes the hostname
    zone_records: list = field(default_factory=list)       # list[ZoneRecord] where the exact record was found
    split_horizon: bool = False                            # True if >1 account holds a matching record
    matches: list = field(default_factory=list)            # list[ResourceMatch] from IP/alias attribution
    notes: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _hostname_from_url(url: str) -> str:
    h = url.strip()
    h = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", h)
    h = h.split("/")[0].split("?")[0]
    h = h.split(":")[0]
    return h.rstrip(".")


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _classify_from_description(description: str, interface_type: str):
    """Map an ENI description/interface type to (resource_type, workload_hint)."""
    desc = description or ""
    itype = (interface_type or "").lower()

    itype_map = {
        "lambda": "Lambda",
        "network_load_balancer": "NLB",
        "nat_gateway": "NAT Gateway",
        "vpc_endpoint": "VPC Endpoint",
        "transit_gateway": "Transit Gateway",
        "gateway_load_balancer": "Gateway Load Balancer",
        "gateway_load_balancer_endpoint": "GWLB Endpoint",
        "efa": "EFA",
    }
    rtype = itype_map.get(itype)

    patterns = [
        (r"^ELB app/([^/]+)/", "ALB"),
        (r"^ELB net/([^/]+)/", "NLB"),
        (r"^ELB (.+)", "ELB (classic)"),
        (r"^AWS Lambda VPC ENI-(.+)", "Lambda"),
        (r"^EFS mount target for (fs-[0-9a-f]+)", "EFS mount target"),
        (r"^Interface for NAT Gateway (nat-[0-9a-f]+)", "NAT Gateway"),
        (r"^VPC Endpoint Interface (vpce-[0-9a-f]+)", "VPC Endpoint"),
        (r"^RDSNetworkInterface", "RDS"),
        (r"^DMSNetworkInterface", "DMS"),
        (r"^ElastiCache (.+)", "ElastiCache"),
        (r"^Redshift (.+)", "Redshift"),
        (r"Network Interface created by API Gateway", "API Gateway (private)"),
        (r"aws-K8S-", "EKS/Kubernetes pod ENI"),
    ]
    workload = None
    for pat, label in patterns:
        m = re.search(pat, desc)
        if m:
            if rtype is None:
                rtype = label
            if m.groups():
                workload = m.group(1)
            break

    if workload is None and desc:
        workload = desc
    return rtype, workload


class InfraResolver:
    def __init__(self, session: Optional[boto3.Session] = None,
                 aggregator_name: str = DEFAULT_AGGREGATOR,
                 aggregator_region: str = AGGREGATOR_REGION,
                 assume_role_name: str = ASSUME_ROLE_NAME):
        # On EC2 this Session uses the instance profile. assume_role_name is the
        # role assumed into a zone-owning account to read its private hosted-zone
        # records (the instance profile must be allowed to assume it).
        self.session = session or boto3.Session()
        self.aggregator_name = aggregator_name
        self.aggregator_region = aggregator_region
        self.assume_role_name = assume_role_name
        self.config = self.session.client("config", region_name=aggregator_region)
        self.sts = self.session.client("sts")
        # Cache of per-account Route53 clients so we don't re-assume repeatedly.
        self._r53_clients: dict[str, object] = {}
        # Cache of the org-wide hosted-zone inventory (from Config).
        self._zone_inventory: Optional[list] = None

    # ---- Step 1: DNS ------------------------------------------------------
    def resolve_dns(self, hostname: str):
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = sorted({i[4][0] for i in infos})
            return ips, None
        except Exception as e:  # noqa: BLE001
            return [], f"{type(e).__name__}: {e}"

    # ---- Config-driven hosted-zone discovery ------------------------------
    def _load_zone_inventory(self) -> list:
        """Enumerate ALL Route53 hosted zones org-wide via the Config aggregator.

        Returns a list of dicts: {accountId, zoneId, zoneName}.
        Cached for the life of the resolver instance.
        """
        if self._zone_inventory is not None:
            return self._zone_inventory

        import json
        expr = ("SELECT accountId, awsRegion, resourceId, resourceName "
                "WHERE resourceType = 'AWS::Route53::HostedZone'")
        zones = []
        kwargs = dict(Expression=expr,
                      ConfigurationAggregatorName=self.aggregator_name,
                      Limit=100)
        try:
            while True:
                resp = self.config.select_aggregate_resource_config(**kwargs)
                for row in resp.get("Results", []):
                    d = json.loads(row)
                    zones.append({
                        "accountId": d.get("accountId"),
                        "zoneId": d.get("resourceId"),
                        "zoneName": (d.get("resourceName") or "").rstrip("."),
                    })
                token = resp.get("NextToken")
                if not token:
                    break
                kwargs["NextToken"] = token
        except Exception as e:  # noqa: BLE001
            # Leave inventory empty; caller will note the failure.
            self._zone_inventory = []
            raise e
        self._zone_inventory = zones
        return zones

    def find_candidate_zones(self, hostname: str) -> list:
        """All hosted zones (across accounts) whose name is a suffix of hostname,
        sorted most-specific (longest zone name) first."""
        candidates = []
        for z in self._load_zone_inventory():
            zname = z["zoneName"]
            if not zname:
                continue
            if hostname == zname or hostname.endswith("." + zname):
                candidates.append(z)
        candidates.sort(key=lambda z: len(z["zoneName"]), reverse=True)
        return candidates

    # ---- Cross-account Route53 client -------------------------------------
    def _route53_for_account(self, account_id: str):
        """Return a Route53 client in the target account by assuming the role
        there. Cached per account. On EC2 the instance profile must be permitted
        to assume <assume_role_name> in each zone-owning account."""
        if account_id in self._r53_clients:
            return self._r53_clients[account_id]

        role_arn = f"arn:aws:iam::{account_id}:role/{self.assume_role_name}"
        creds = self.sts.assume_role(
            RoleArn=role_arn, RoleSessionName="url-infra-resolver")["Credentials"]
        client = boto3.client(
            "route53",
            region_name="us-east-1",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        self._r53_clients[account_id] = client
        return client

    def lookup_record_in_zone(self, zone: dict, hostname: str) -> Optional[ZoneRecord]:
        """Read the exact record for hostname in a specific (account, zone)."""
        try:
            r53 = self._route53_for_account(zone["accountId"])
            resp = r53.list_resource_record_sets(
                HostedZoneId=zone["zoneId"],
                StartRecordName=hostname,
                MaxItems="5",
            )
        except Exception:  # noqa: BLE001 - skip zones we can't read
            return None

        for rr in resp.get("ResourceRecordSets", []):
            # list_resource_record_sets returns records at/after the start name;
            # filter to the EXACT hostname (learned from real data where nearby
            # records leaked into the response).
            if rr.get("Name", "").rstrip(".") != hostname:
                continue
            zr = ZoneRecord(
                zone_account_id=zone["accountId"],
                zone_id=zone["zoneId"],
                zone_name=zone["zoneName"],
                record_type=rr.get("Type"),
            )
            if "AliasTarget" in rr:
                zr.alias_target = rr["AliasTarget"].get("DNSName", "").rstrip(".")
            else:
                zr.values = [v.get("Value") for v in rr.get("ResourceRecords", [])]
            return zr
        return None

    def lookup_route53(self, hostname: str, result: ResolveResult) -> None:
        """Config-driven, multi-account, multi-zone record discovery."""
        try:
            candidates = self.find_candidate_zones(hostname)
        except Exception as e:  # noqa: BLE001
            result.notes.append(f"Config hosted-zone inventory failed: {e}")
            return

        result.candidate_zones = candidates
        if not candidates:
            result.notes.append("No hosted zone (in Config inventory) suffixes the hostname.")
            return

        found = []
        for zone in candidates:
            zr = self.lookup_record_in_zone(zone, hostname)
            if zr:
                found.append(zr)

        result.zone_records = [asdict(z) for z in found]
        if len(found) > 1:
            result.split_horizon = True
            result.notes.append(
                f"Split-horizon: the record exists in {len(found)} zones across "
                f"accounts {sorted({z.zone_account_id for z in found})}.")
        if not found:
            result.notes.append(
                "Hostname suffixes a known zone, but no exact record found in any "
                "candidate zone (record may not exist or be in an unreadable account).")

    def attribute_ip(self, ip: str) -> list:
        expr = (
            "SELECT accountId, awsRegion, resourceId, "
            "configuration.privateIpAddress, configuration.description, "
            "configuration.interfaceType "
            "WHERE resourceType = 'AWS::EC2::NetworkInterface' "
            f"AND configuration.privateIpAddress = '{ip}'"
        )
        try:
            resp = self.config.select_aggregate_resource_config(
                Expression=expr,
                ConfigurationAggregatorName=self.aggregator_name,
                Limit=25,
            )
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(private_ip=ip, description=f"Config query error: {e}")]

        import json
        matches = []
        for row in resp.get("Results", []):
            d = json.loads(row)
            cfg = d.get("configuration", {}) or {}
            desc = cfg.get("description")
            itype = cfg.get("interfaceType")
            rtype, workload = _classify_from_description(desc, itype)
            matches.append(ResourceMatch(
                account_id=d.get("accountId"),
                region=d.get("awsRegion"),
                resource_id=d.get("resourceId"),
                private_ip=cfg.get("privateIpAddress") or ip,
                description=desc,
                interface_type=itype,
                resource_type=rtype,
                workload_hint=workload,
            ))
        return matches

    def attribute_alias_target(self, alias_dns: str) -> list:
        """Attribute an ELB alias DNS name (e.g.
        internal-kh-test-progress-123.us-west-2.elb.amazonaws.com) to an account
        by resolving the ELB's ENIs via the Config aggregator.

        Strategy: an ELB's ENIs carry a description containing the ELB name, so
        we search ENIs whose description references the alias's ELB name.
        """
        # Extract the ELB name from the alias DNS.
        #   internal-<name>-<hash>.<region>.elb.amazonaws.com  (ALB, internal)
        #   <name>-<hash>.<region>.elb.amazonaws.com           (ALB)
        #   <name>-<hash>.elb.<region>.amazonaws.com           (NLB)
        first = alias_dns.split(".")[0]
        elb_name = first
        if elb_name.startswith("internal-"):
            elb_name = elb_name[len("internal-"):]
        # Drop the trailing -<hash> segment.
        elb_name = re.sub(r"-[0-9a-f]{6,}$", "", elb_name)

        import json
        # ENI descriptions look like "ELB app/<name>/..." or "ELB net/<name>/..."
        # Config LIKE can't lead with a wildcard, so anchor on "ELB ".
        expr = (
            "SELECT accountId, awsRegion, resourceId, "
            "configuration.privateIpAddress, configuration.description, "
            "configuration.interfaceType "
            "WHERE resourceType = 'AWS::EC2::NetworkInterface' "
            "AND configuration.description LIKE 'ELB %'"
        )
        matches = []
        try:
            kwargs = dict(Expression=expr,
                          ConfigurationAggregatorName=self.aggregator_name,
                          Limit=100)
            while True:
                resp = self.config.select_aggregate_resource_config(**kwargs)
                for row in resp.get("Results", []):
                    d = json.loads(row)
                    cfg = d.get("configuration", {}) or {}
                    desc = cfg.get("description") or ""
                    if elb_name and elb_name in desc:
                        rtype, workload = _classify_from_description(
                            desc, cfg.get("interfaceType"))
                        matches.append(ResourceMatch(
                            account_id=d.get("accountId"),
                            region=d.get("awsRegion"),
                            resource_id=d.get("resourceId"),
                            private_ip=cfg.get("privateIpAddress"),
                            description=desc,
                            interface_type=cfg.get("interfaceType"),
                            resource_type=rtype,
                            workload_hint=workload,
                        ))
                token = resp.get("NextToken")
                if not token:
                    break
                kwargs["NextToken"] = token
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(description=f"Alias attribution error: {e}",
                                  workload_hint=elb_name)]
        return matches

    def resolve(self, url: str) -> ResolveResult:
        hostname = _hostname_from_url(url)
        result = ResolveResult(url=url, hostname=hostname)

        # Step 1: live DNS (works only on-VPC for .csaa.pri; may be empty off-VPC).
        ips, dns_err = self.resolve_dns(hostname)
        result.resolved_ips = ips
        result.dns_error = dns_err

        # Step 2: Config-driven multi-zone Route53 record discovery.
        self.lookup_route53(hostname, result)

        seen = set()

        def _add(m: ResourceMatch):
            key = (m.account_id, m.resource_id, m.private_ip)
            if key in seen:
                return
            seen.add(key)
            result.matches.append(m)

        # Step 3a: attribute any private IPs from live DNS.
        for ip in ips:
            if not _is_private_ip(ip):
                result.notes.append(
                    f"{ip} is public/AWS-managed (e.g. API Gateway/CloudFront) -- "
                    f"using Route53 alias target for attribution instead.")
                continue
            for m in self.attribute_ip(ip):
                _add(m)

        # Step 3b: attribute via alias targets from the Route53 records (the more
        # precise path -- names the ELB directly, no DNS needed).
        for zr in result.zone_records:
            alias = zr.get("alias_target")
            if alias and "elb.amazonaws.com" in alias:
                for m in self.attribute_alias_target(alias):
                    _add(m)

        if not result.matches and not result.zone_records:
            result.notes.append(
                "No ENI match and no Route53 record. Target may be an AWS-managed "
                "endpoint (API Gateway/CloudFront), in a region outside the "
                "'us-regions' aggregator, or not yet recorded by Config.")

        result.matches = [asdict(m) for m in result.matches]
        return result


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("usage:")
        print("  python resolver.py <url> [aws_profile]")
        print("  python resolver.py --ip <private_ip> [aws_profile]   (test attribution off-VPC)")
        sys.exit(1)

    if sys.argv[1] == "--ip":
        if len(sys.argv) < 3:
            print("usage: python resolver.py --ip <private_ip> [aws_profile]")
            sys.exit(1)
        ip = sys.argv[2]
        profile = sys.argv[3] if len(sys.argv) > 3 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        matches = [asdict(m) for m in r.attribute_ip(ip)]
        print(json.dumps({"ip": ip, "matches": matches}, indent=2, default=str))
    else:
        url = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        print(json.dumps(r.resolve(url).to_dict(), indent=2, default=str))
