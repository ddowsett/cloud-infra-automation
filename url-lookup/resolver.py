"""
Core resolver: URL -> infrastructure location.

Chain:
  1. Resolve the hostname via DNS (live) to IP address(es).
  2. Look up the Route 53 record for the hostname -- discovering candidate hosted
     zones across ALL accounts via the AWS Config org aggregator, then reading the
     exact record in each zone-owning account (assuming CsaaInfraResolverReadRole).
     Captures alias targets (ELB/CloudFront) and plain A/CNAME record values.
  3. Attribute to an owning account + resource via the Config aggregator:
       a. private IPs (from live DNS or A-record values) -> ENI
       b. ELB alias targets                              -> ENI (by ELB name)
       c. CloudFront (hostname is a distribution alias, or record points to
          *.cloudfront.net)                              -> CloudFront distribution
       d. Akamai edgekey/akamaiedge CNAME -> follow the 'origin-<host>' variant
          (CSAA convention) and re-attribute.
  4. Classify the resource type from the ENI description / interface type.

Credentials: default boto3 chain. On the EC2 instance this is the
CloudInfraEc2Role instance profile. For local testing, pass a profile name.

Read-only: only DNS lookups and Config/Route53 describe/select calls.
"""

from __future__ import annotations

import ipaddress
import socket
import re
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional

import boto3


DEFAULT_AGGREGATOR = os.environ.get("RESOLVER_AGGREGATOR", "us-regions")
AGGREGATOR_REGION = os.environ.get("RESOLVER_AGGREGATOR_REGION", "us-west-2")
ASSUME_ROLE_NAME = os.environ.get("RESOLVER_ASSUME_ROLE", "CsaaInfraResolverReadRole")

# CDN CNAME suffixes we recognize.
AKAMAI_SUFFIXES = ("edgekey.net", "akamaiedge.net", "edgesuite.net")
CLOUDFRONT_SUFFIX = "cloudfront.net"


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
    attached_instance_id: Optional[str] = None
    source: Optional[str] = None  # dns-ip | a-record-ip | alias | cloudfront-alias | cloudfront-domain


@dataclass
class ZoneRecord:
    zone_account_id: Optional[str] = None
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    record_type: Optional[str] = None
    alias_target: Optional[str] = None
    values: list = field(default_factory=list)


@dataclass
class ResolveResult:
    url: str = ""
    hostname: str = ""
    resolved_ips: list = field(default_factory=list)
    dns_error: Optional[str] = None
    candidate_zones: list = field(default_factory=list)
    zone_records: list = field(default_factory=list)
    split_horizon: bool = False
    matches: list = field(default_factory=list)
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
        self.session = session or boto3.Session()
        self.aggregator_name = aggregator_name
        self.aggregator_region = aggregator_region
        self.assume_role_name = assume_role_name
        self.config = self.session.client("config", region_name=aggregator_region)
        self.sts = self.session.client("sts")
        self._r53_clients: dict[str, object] = {}
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
        if self._zone_inventory is not None:
            return self._zone_inventory
        expr = ("SELECT accountId, awsRegion, resourceId, resourceName "
                "WHERE resourceType = 'AWS::Route53::HostedZone'")
        zones = []
        kwargs = dict(Expression=expr,
                      ConfigurationAggregatorName=self.aggregator_name, Limit=100)
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
        self._zone_inventory = zones
        return zones

    def find_candidate_zones(self, hostname: str) -> list:
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
    def _current_account_id(self) -> Optional[str]:
        if not hasattr(self, "_caller_acct"):
            try:
                self._caller_acct = self.sts.get_caller_identity()["Account"]
            except Exception:  # noqa: BLE001
                self._caller_acct = None
        return self._caller_acct

    def _route53_for_account(self, account_id: str):
        if account_id in self._r53_clients:
            return self._r53_clients[account_id]
        if account_id == self._current_account_id():
            client = self.session.client("route53", region_name="us-east-1")
            self._r53_clients[account_id] = client
            return client
        role_arn = f"arn:aws:iam::{account_id}:role/{self.assume_role_name}"
        creds = self.sts.assume_role(
            RoleArn=role_arn, RoleSessionName="url-infra-resolver")["Credentials"]
        client = boto3.client(
            "route53", region_name="us-east-1",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        self._r53_clients[account_id] = client
        return client

    def lookup_record_in_zone(self, zone: dict, hostname: str) -> Optional[ZoneRecord]:
        try:
            r53 = self._route53_for_account(zone["accountId"])
            resp = r53.list_resource_record_sets(
                HostedZoneId=zone["zoneId"], StartRecordName=hostname, MaxItems="5")
        except Exception:  # noqa: BLE001
            return None
        for rr in resp.get("ResourceRecordSets", []):
            if rr.get("Name", "").rstrip(".") != hostname:
                continue
            zr = ZoneRecord(
                zone_account_id=zone["accountId"], zone_id=zone["zoneId"],
                zone_name=zone["zoneName"], record_type=rr.get("Type"))
            if "AliasTarget" in rr:
                zr.alias_target = rr["AliasTarget"].get("DNSName", "").rstrip(".")
            else:
                zr.values = [v.get("Value") for v in rr.get("ResourceRecords", [])]
            return zr
        return None

    def lookup_route53(self, hostname: str, result: ResolveResult) -> None:
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

    # ---- Step 3a/b: ENI-based attribution ---------------------------------
    def attribute_ip(self, ip: str, source: Optional[str] = None) -> list:
        expr = (
            "SELECT accountId, awsRegion, resourceId, "
            "configuration.privateIpAddress, configuration.description, "
            "configuration.interfaceType, configuration.attachment.instanceId "
            "WHERE resourceType = 'AWS::EC2::NetworkInterface' "
            f"AND configuration.privateIpAddress = '{ip}'"
        )
        try:
            resp = self.config.select_aggregate_resource_config(
                Expression=expr, ConfigurationAggregatorName=self.aggregator_name, Limit=25)
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(private_ip=ip, description=f"Config query error: {e}", source=source)]
        matches = []
        for row in resp.get("Results", []):
            d = json.loads(row)
            cfg = d.get("configuration", {}) or {}
            desc = cfg.get("description")
            itype = cfg.get("interfaceType")
            instance_id = (cfg.get("attachment") or {}).get("instanceId")
            rtype, workload = _classify_from_description(desc, itype)
            if rtype is None and instance_id:
                rtype = "EC2 instance"
                workload = instance_id
            matches.append(ResourceMatch(
                account_id=d.get("accountId"), region=d.get("awsRegion"),
                resource_id=d.get("resourceId"),
                private_ip=cfg.get("privateIpAddress") or ip,
                description=desc, interface_type=itype,
                resource_type=rtype, workload_hint=workload,
                attached_instance_id=instance_id, source=source))
        return matches

    def attribute_alias_target(self, alias_dns: str) -> list:
        first = alias_dns.split(".")[0]
        elb_name = first
        if elb_name.startswith("internal-"):
            elb_name = elb_name[len("internal-"):]
        elb_name = re.sub(r"-[0-9a-f]{6,}$", "", elb_name)
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
                          ConfigurationAggregatorName=self.aggregator_name, Limit=100)
            while True:
                resp = self.config.select_aggregate_resource_config(**kwargs)
                for row in resp.get("Results", []):
                    d = json.loads(row)
                    cfg = d.get("configuration", {}) or {}
                    desc = cfg.get("description") or ""
                    if elb_name and elb_name in desc:
                        rtype, workload = _classify_from_description(desc, cfg.get("interfaceType"))
                        matches.append(ResourceMatch(
                            account_id=d.get("accountId"), region=d.get("awsRegion"),
                            resource_id=d.get("resourceId"),
                            private_ip=cfg.get("privateIpAddress"),
                            description=desc, interface_type=cfg.get("interfaceType"),
                            resource_type=rtype, workload_hint=workload, source="alias"))
                token = resp.get("NextToken")
                if not token:
                    break
                kwargs["NextToken"] = token
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(description=f"Alias attribution error: {e}",
                                  workload_hint=elb_name, source="alias")]
        return matches

    # ---- Step 3c: CloudFront attribution ----------------------------------
    def _cf_match(self, where_clause: str, source: str) -> list:
        """Run a CloudFront distribution query and build matches."""
        expr = (
            "SELECT accountId, resourceId, configuration.domainName, "
            "configuration.distributionConfig.aliases.items "
            "WHERE resourceType = 'AWS::CloudFront::Distribution' "
            f"AND {where_clause}"
        )
        matches = []
        try:
            resp = self.config.select_aggregate_resource_config(
                Expression=expr, ConfigurationAggregatorName=self.aggregator_name, Limit=10)
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(description=f"CloudFront query error: {e}", source=source)]
        for row in resp.get("Results", []):
            d = json.loads(row)
            cfg = d.get("configuration", {}) or {}
            matches.append(ResourceMatch(
                account_id=d.get("accountId"),
                region="global",
                resource_id=d.get("resourceId"),
                resource_type="CloudFront distribution",
                workload_hint=cfg.get("domainName"),
                source=source))
        return matches

    def attribute_cloudfront_by_alias(self, hostname: str) -> list:
        """Find a CloudFront distribution that lists this hostname in its aliases.
        This resolves CDN-fronted hostnames directly, without the Akamai/origin hop."""
        return self._cf_match(
            f"configuration.distributionConfig.aliases.items = '{hostname}'",
            source="cloudfront-alias")

    def attribute_cloudfront_by_domain(self, cf_domain: str) -> list:
        """Find a CloudFront distribution by its *.cloudfront.net domainName."""
        return self._cf_match(
            f"configuration.domainName = '{cf_domain}'",
            source="cloudfront-domain")

    # ---- Orchestration ----------------------------------------------------
    def resolve(self, url: str) -> ResolveResult:
        hostname = _hostname_from_url(url)
        result = ResolveResult(url=url, hostname=hostname)

        ips, dns_err = self.resolve_dns(hostname)
        result.resolved_ips = ips
        result.dns_error = dns_err

        self.lookup_route53(hostname, result)

        seen = set()

        def _add(m: ResourceMatch):
            key = (m.account_id, m.resource_id, m.private_ip)
            if key in seen:
                return
            seen.add(key)
            result.matches.append(m)

        # 3c-primary: does any CloudFront distribution claim this hostname as an
        # alias? Works even for the Akamai-fronted public name (CF lists both the
        # public and origin- aliases). Most robust CDN attribution.
        for m in self.attribute_cloudfront_by_alias(hostname):
            if m.account_id:
                _add(m)

        # 3a: private IPs from live DNS.
        for ip in ips:
            if not _is_private_ip(ip):
                result.notes.append(
                    f"{ip} is public/AWS-managed (CDN/API Gateway/CloudFront) -- "
                    f"using Route53 record / CloudFront aliases for attribution instead.")
                continue
            for m in self.attribute_ip(ip, source="dns-ip"):
                _add(m)

        # 3a-bis + 3b + 3c-secondary: walk the Route53 records.
        for zr in result.zone_records:
            # Plain A-record private IPs.
            for ip in zr.get("values", []) or []:
                if _is_private_ip(ip):
                    for m in self.attribute_ip(ip, source="a-record-ip"):
                        _add(m)
                    continue
                # CNAME value pointing to CloudFront?
                val = (ip or "").rstrip(".")
                if val.endswith(CLOUDFRONT_SUFFIX):
                    for m in self.attribute_cloudfront_by_domain(val):
                        _add(m)
                elif any(val.endswith(s) for s in AKAMAI_SUFFIXES):
                    self._follow_akamai_origin(hostname, result, _add)
                else:
                    result.notes.append(
                        f"{val} (record value) is not a private IP or known AWS/CDN target "
                        f"-- skipping ENI attribution.")

            # Alias target.
            alias = (zr.get("alias_target") or "").rstrip(".")
            if not alias:
                continue
            if alias.endswith(CLOUDFRONT_SUFFIX):
                cf = self.attribute_cloudfront_by_domain(alias)
                if any(m.account_id for m in cf):
                    for m in cf:
                        if m.account_id:
                            _add(m)
                else:
                    result.notes.append(
                        f"Record aliases to CloudFront '{alias}' but no matching "
                        f"distribution found in Config.")
            elif "elb.amazonaws.com" in alias:
                elbm = self.attribute_alias_target(alias)
                if elbm:
                    for m in elbm:
                        _add(m)
                else:
                    result.notes.append(
                        f"Record aliases to '{alias}' but no backing ENI/resource was "
                        f"found in Config -- possibly a deleted/stale ELB.")

        # 3d: Akamai origin-follow if the record CNAMEs to Akamai and we haven't
        # already attributed anything.
        if not result.matches:
            for zr in result.zone_records:
                for v in (zr.get("values", []) or []):
                    val = (v or "").rstrip(".")
                    if any(val.endswith(s) for s in AKAMAI_SUFFIXES):
                        self._follow_akamai_origin(hostname, result, _add)
                        break

        if not result.matches and not result.zone_records:
            result.notes.append(
                "No ENI/CloudFront match and no Route53 record. Target may be an "
                "AWS-managed endpoint, external, in a region outside the "
                "'us-regions' aggregator, or not yet recorded by Config.")
        elif not result.matches and result.zone_records:
            result.notes.append(
                "Found a Route53 record but could not attribute it to a resource "
                "(see record values/alias above).")

        result.matches = [asdict(m) for m in result.matches]
        return result

    def _follow_akamai_origin(self, hostname: str, result: ResolveResult, _add) -> None:
        """CSAA convention: an Akamai-fronted host 'X' has an origin record
        'origin-X' that points at the real AWS target (often CloudFront). Resolve
        the origin- variant and attribute it."""
        if hostname.startswith("origin-"):
            return  # avoid recursion
        origin_host = "origin-" + hostname
        result.notes.append(
            f"Akamai CDN detected; following CSAA origin convention -> {origin_host}")
        # Look up the origin- record directly (reuse zone discovery).
        try:
            candidates = self.find_candidate_zones(origin_host)
        except Exception:  # noqa: BLE001
            return
        for zone in candidates:
            zr = self.lookup_record_in_zone(zone, origin_host)
            if not zr:
                continue
            alias = (zr.alias_target or "").rstrip(".")
            if alias.endswith(CLOUDFRONT_SUFFIX):
                for m in self.attribute_cloudfront_by_domain(alias):
                    if m.account_id:
                        m.source = "akamai-origin-cloudfront"
                        _add(m)
            elif "elb.amazonaws.com" in alias:
                for m in self.attribute_alias_target(alias):
                    m.source = "akamai-origin-elb"
                    _add(m)
            else:
                for v in (zr.values or []):
                    vv = (v or "").rstrip(".")
                    if vv.endswith(CLOUDFRONT_SUFFIX):
                        for m in self.attribute_cloudfront_by_domain(vv):
                            if m.account_id:
                                m.source = "akamai-origin-cloudfront"
                                _add(m)
                    elif _is_private_ip(vv):
                        for m in self.attribute_ip(vv, source="akamai-origin-ip"):
                            _add(m)
            return


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage:")
        print("  python resolver.py <url> [aws_profile]")
        print("  python resolver.py --ip <private_ip> [aws_profile]")
        sys.exit(1)

    if sys.argv[1] == "--ip":
        ip = sys.argv[2]
        profile = sys.argv[3] if len(sys.argv) > 3 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        print(json.dumps({"ip": ip, "matches": [asdict(m) for m in r.attribute_ip(ip, source="manual")]},
                         indent=2, default=str))
    else:
        url = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        print(json.dumps(r.resolve(url).to_dict(), indent=2, default=str))
