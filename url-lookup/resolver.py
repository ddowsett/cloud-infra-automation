"""
Core resolver: URL -> infrastructure location.

Resolution ladder (per resolved IP, stop at first tier that answers):
  1. Exact ENI match (Config AWS::EC2::NetworkInterface by private IP)
       -> account + resource + region
  2. Containing subnet (Config AWS::EC2::Subnet whose CIDR contains the IP)
       -> account + region + VPC + subnet   (source: subnet-cidr)
  3. Containing VPC (Config AWS::EC2::VPC whose CIDR contains the IP)
       -> account + region + VPC                 (source: vpc-cidr)
  4. CSAA CIDR list (ip_blocks.json)              -> network location label
  5. RFC1918 / public-internet generic classification

Hostname chain (before IP attribution):
  - DNS (live) + Config-discovered Route 53 records across accounts.
  - CloudFront attribution (distribution aliases / *.cloudfront.net domain).
  - Akamai edgekey/akamaiedge -> follow CSAA 'origin-<host>' convention.
  - ELB alias attribution.

Credentials: default boto3 chain (CloudInfraEc2Role on the instance).
Read-only: DNS + Config/Route53 describe/select only.
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

AKAMAI_SUFFIXES = ("edgekey.net", "akamaiedge.net", "edgesuite.net")
CLOUDFRONT_SUFFIX = "cloudfront.net"


def _classify_endpoint_service(service_name: str) -> str:
    """Human label for a VPC endpoint's service -- the real terminus of an
    ELB -> VPC-endpoint PrivateLink path."""
    s = (service_name or "").lower()
    if s.endswith(".execute-api"):
        return "Private API Gateway (execute-api via PrivateLink)"
    if ".vpce-svc-" in s or "vpce-svc-" in s:
        return "Cross-account PrivateLink endpoint service (provider owns the backend)"
    if s.startswith("com.amazonaws."):
        # e.g. com.amazonaws.us-west-2.s3 / .dynamodb / .elasticloadbalancing
        svc = s.rsplit(".", 1)[-1]
        return f"AWS service endpoint ({svc})"
    return f"VPC endpoint service: {service_name}"


def _is_elb_dns(name: str) -> bool:
    """True for either ELB DNS format:
       ALB: <name>-<hash>.<region>.elb.amazonaws.com
       NLB: <name>-<hash>.elb.<region>.amazonaws.com
    Both contain '.elb.' and end in '.amazonaws.com'."""
    n = (name or "").rstrip(".").lower()
    return ".elb." in n and n.endswith(".amazonaws.com")

# Path to the CSAA CIDR -> location map (tiers 4/5 fallback). Sits next to this file.
IP_BLOCKS_FILE = os.environ.get(
    "RESOLVER_IP_BLOCKS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_blocks.json"))

# Accounts excluded from discovery/attribution (e.g. sandbox). Sits next to this file.
EXCLUDED_ACCOUNTS_FILE = os.environ.get(
    "RESOLVER_EXCLUDED_ACCOUNTS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "excluded_accounts.json"))


def _load_excluded_accounts():
    try:
        with open(EXCLUDED_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {e["account_id"] for e in data.get("excluded_accounts", []) if e.get("account_id")}
    except Exception:  # noqa: BLE001 - missing file = exclude nothing
        return set()


# Module-level set of excluded account IDs.
EXCLUDED_ACCOUNTS = _load_excluded_accounts()


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
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    source: Optional[str] = None


@dataclass
class IpLocation:
    ip: Optional[str] = None
    location: Optional[str] = None
    cidr: Optional[str] = None
    source: Optional[str] = None  # cidr-list | rfc1918 | public


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
    ip_locations: list = field(default_factory=list)
    trace: list = field(default_factory=list)   # deeper hop chain for ELB-fronted targets
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
        "lambda": "Lambda", "network_load_balancer": "NLB", "nat_gateway": "NAT Gateway",
        "vpc_endpoint": "VPC Endpoint", "transit_gateway": "Transit Gateway",
        "gateway_load_balancer": "Gateway Load Balancer",
        "gateway_load_balancer_endpoint": "GWLB Endpoint", "efa": "EFA",
    }
    rtype = itype_map.get(itype)
    patterns = [
        (r"^ELB app/([^/]+)/", "ALB"), (r"^ELB net/([^/]+)/", "NLB"), (r"^ELB (.+)", "ELB (classic)"),
        (r"^AWS Lambda VPC ENI-(.+)", "Lambda"),
        (r"^EFS mount target for (fs-[0-9a-f]+)", "EFS mount target"),
        (r"^Interface for NAT Gateway (nat-[0-9a-f]+)", "NAT Gateway"),
        (r"^VPC Endpoint Interface (vpce-[0-9a-f]+)", "VPC Endpoint"),
        (r"^RDSNetworkInterface", "RDS"), (r"^DMSNetworkInterface", "DMS"),
        (r"^ElastiCache (.+)", "ElastiCache"), (r"^Redshift (.+)", "Redshift"),
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


def _load_ip_blocks():
    try:
        with open(IP_BLOCKS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        blocks = []
        for b in data.get("blocks", []):
            try:
                blocks.append((ipaddress.ip_network(b["cidr"]), b["location"], b["cidr"]))
            except (KeyError, ValueError):
                continue
        return blocks
    except Exception:  # noqa: BLE001 - missing file just disables tier 4
        return []


_IP_BLOCKS = _load_ip_blocks()


def classify_ip_location(ip: str) -> Optional[IpLocation]:
    """Tiers 4/5: CSAA CIDR list, else RFC1918/public classification."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    # Tier 4: explicit CSAA blocks, longest-prefix match wins.
    best = None
    for net, label, cidr in _IP_BLOCKS:
        if addr.version == net.version and addr in net:
            if best is None or net.prefixlen > best[0].prefixlen:
                best = (net, label, cidr)
    if best:
        return IpLocation(ip=ip, location=best[1], cidr=best[2], source="cidr-list")
    # Tier 5: generic.
    if addr.is_private:
        return IpLocation(ip=ip,
                          location="Private/RFC1918 (internal, not attributed to an AWS resource)",
                          source="rfc1918")
    return IpLocation(ip=ip, location="Public internet (outside CSAA)", source="public")


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
        self._subnet_inventory: Optional[list] = None
        self._vpc_inventory: Optional[list] = None

    # ---- Step 1: DNS ------------------------------------------------------
    def resolve_dns(self, hostname: str):
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = sorted({i[4][0] for i in infos})
            return ips, None
        except Exception as e:  # noqa: BLE001
            return [], f"{type(e).__name__}: {e}"

    # ---- Config inventories (cached) --------------------------------------
    def _select_all(self, expr: str) -> list:
        rows = []
        kwargs = dict(Expression=expr, ConfigurationAggregatorName=self.aggregator_name, Limit=100)
        while True:
            resp = self.config.select_aggregate_resource_config(**kwargs)
            rows.extend(resp.get("Results", []))
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
        return rows

    def _load_zone_inventory(self) -> list:
        if self._zone_inventory is not None:
            return self._zone_inventory
        rows = self._select_all(
            "SELECT accountId, awsRegion, resourceId, resourceName "
            "WHERE resourceType = 'AWS::Route53::HostedZone'")
        zones = []
        for row in rows:
            d = json.loads(row)
            if d.get("accountId") in EXCLUDED_ACCOUNTS:
                continue
            zones.append({"accountId": d.get("accountId"), "zoneId": d.get("resourceId"),
                          "zoneName": (d.get("resourceName") or "").rstrip(".")})
        self._zone_inventory = zones
        return zones

    def _load_subnet_inventory(self) -> list:
        if self._subnet_inventory is not None:
            return self._subnet_inventory
        rows = self._select_all(
            "SELECT accountId, awsRegion, resourceId, configuration.cidrBlock, "
            "configuration.vpcId "
            "WHERE resourceType = 'AWS::EC2::Subnet'")
        subs = []
        for row in rows:
            d = json.loads(row)
            if d.get("accountId") in EXCLUDED_ACCOUNTS:
                continue
            c = d.get("configuration", {}) or {}
            cidr = c.get("cidrBlock")
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr)
            except ValueError:
                continue
            subs.append({"net": net, "accountId": d.get("accountId"),
                         "region": d.get("awsRegion"), "subnetId": d.get("resourceId"),
                         "vpcId": c.get("vpcId")})
        self._subnet_inventory = subs
        return subs

    def _load_vpc_inventory(self) -> list:
        if self._vpc_inventory is not None:
            return self._vpc_inventory
        rows = self._select_all(
            "SELECT accountId, awsRegion, resourceId, configuration.cidrBlock "
            "WHERE resourceType = 'AWS::EC2::VPC'")
        vpcs = []
        for row in rows:
            d = json.loads(row)
            if d.get("accountId") in EXCLUDED_ACCOUNTS:
                continue
            c = d.get("configuration", {}) or {}
            cidr = c.get("cidrBlock")
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr)
            except ValueError:
                continue
            vpcs.append({"net": net, "accountId": d.get("accountId"),
                         "region": d.get("awsRegion"), "vpcId": d.get("resourceId")})
        self._vpc_inventory = vpcs
        return vpcs

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

    # ---- Cross-account Route53 -------------------------------------------
    def _current_account_id(self) -> Optional[str]:
        if not hasattr(self, "_caller_acct"):
            try:
                self._caller_acct = self.sts.get_caller_identity()["Account"]
            except Exception:  # noqa: BLE001
                self._caller_acct = None
        return self._caller_acct

    def _creds_for_account(self, account_id: str):
        """Return credentials kwargs for a client in the target account.
        Empty dict if we're already that account (use base session)."""
        if account_id == self._current_account_id():
            return {}
        if not hasattr(self, "_creds_cache"):
            self._creds_cache = {}
        if account_id not in self._creds_cache:
            role_arn = f"arn:aws:iam::{account_id}:role/{self.assume_role_name}"
            c = self.sts.assume_role(RoleArn=role_arn,
                                     RoleSessionName="url-infra-resolver")["Credentials"]
            self._creds_cache[account_id] = {
                "aws_access_key_id": c["AccessKeyId"],
                "aws_secret_access_key": c["SecretAccessKey"],
                "aws_session_token": c["SessionToken"],
            }
        return self._creds_cache[account_id]

    def _client_for_account(self, service: str, account_id: str, region: str):
        """Generic cross-account client (assumes the spoke role as needed)."""
        key = (service, account_id, region)
        if not hasattr(self, "_svc_clients"):
            self._svc_clients = {}
        if key not in self._svc_clients:
            creds = self._creds_for_account(account_id)
            if creds:
                self._svc_clients[key] = boto3.client(service, region_name=region, **creds)
            else:
                self._svc_clients[key] = self.session.client(service, region_name=region)
        return self._svc_clients[key]

    def _route53_for_account(self, account_id: str):
        return self._client_for_account("route53", account_id, "us-east-1")

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
            zr = ZoneRecord(zone_account_id=zone["accountId"], zone_id=zone["zoneId"],
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
                "candidate zone.")

    # ---- Tier 1: ENI ------------------------------------------------------
    def attribute_ip_eni(self, ip: str, source: str = "eni") -> list:
        expr = (
            "SELECT accountId, awsRegion, resourceId, configuration.privateIpAddress, "
            "configuration.description, configuration.interfaceType, "
            "configuration.attachment.instanceId, configuration.vpcId, configuration.subnetId "
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
            if d.get("accountId") in EXCLUDED_ACCOUNTS:
                continue
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
                resource_id=d.get("resourceId"), private_ip=cfg.get("privateIpAddress") or ip,
                description=desc, interface_type=itype, resource_type=rtype,
                workload_hint=workload, attached_instance_id=instance_id,
                vpc_id=cfg.get("vpcId"), subnet_id=cfg.get("subnetId"), source=source))
        return matches

    # ---- Tiers 2/3: subnet / VPC containment ------------------------------
    def attribute_ip_by_network(self, ip: str) -> Optional[ResourceMatch]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        # Tier 2: most-specific containing subnet.
        best = None
        for s in self._load_subnet_inventory():
            net = s["net"]
            if addr.version == net.version and addr in net:
                if best is None or net.prefixlen > best["net"].prefixlen:
                    best = s
        if best:
            return ResourceMatch(
                account_id=best["accountId"], region=best["region"],
                resource_id=best["subnetId"], private_ip=ip,
                resource_type="Subnet (no ENI for exact IP)",
                workload_hint=f"in {best['vpcId']}", vpc_id=best["vpcId"],
                subnet_id=best["subnetId"], source="subnet-cidr")
        # Tier 3: containing VPC.
        bestv = None
        for v in self._load_vpc_inventory():
            net = v["net"]
            if addr.version == net.version and addr in net:
                if bestv is None or net.prefixlen > bestv["net"].prefixlen:
                    bestv = v
        if bestv:
            return ResourceMatch(
                account_id=bestv["accountId"], region=bestv["region"],
                resource_id=bestv["vpcId"], private_ip=ip,
                resource_type="VPC (no ENI/subnet for exact IP)",
                vpc_id=bestv["vpcId"], source="vpc-cidr")
        return None

    # ---- CloudFront / ELB alias attribution -------------------------------
    def _cf_match(self, where_clause: str, source: str) -> list:
        expr = ("SELECT accountId, resourceId, configuration.domainName, "
                "configuration.distributionConfig.aliases.items "
                "WHERE resourceType = 'AWS::CloudFront::Distribution' "
                f"AND {where_clause}")
        matches = []
        try:
            resp = self.config.select_aggregate_resource_config(
                Expression=expr, ConfigurationAggregatorName=self.aggregator_name, Limit=10)
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(description=f"CloudFront query error: {e}", source=source)]
        for row in resp.get("Results", []):
            d = json.loads(row)
            if d.get("accountId") in EXCLUDED_ACCOUNTS:
                continue
            cfg = d.get("configuration", {}) or {}
            matches.append(ResourceMatch(
                account_id=d.get("accountId"), region="global", resource_id=d.get("resourceId"),
                resource_type="CloudFront distribution", workload_hint=cfg.get("domainName"),
                source=source))
        return matches

    def attribute_cloudfront_by_alias(self, hostname: str) -> list:
        return self._cf_match(
            f"configuration.distributionConfig.aliases.items = '{hostname}'", "cloudfront-alias")

    def attribute_cloudfront_by_domain(self, cf_domain: str) -> list:
        return self._cf_match(f"configuration.domainName = '{cf_domain}'", "cloudfront-domain")

    def attribute_alias_target(self, alias_dns: str) -> list:
        """Map an ELB alias DNS name to exactly one load balancer via Config's
        AWS::ElasticLoadBalancingV2::LoadBalancer dNSName attribute. Precise:
        one DNS name -> one LB -> one account (no ENI fan-out / name lookalikes)."""
        target = (alias_dns or "").rstrip(".")
        expr = ("SELECT accountId, awsRegion, resourceId, resourceName, arn, "
                "configuration.type, configuration.scheme, configuration.dNSName, "
                "configuration.loadBalancerArn "
                "WHERE resourceType = 'AWS::ElasticLoadBalancingV2::LoadBalancer' "
                f"AND configuration.dNSName = '{target}'")
        matches = []
        try:
            resp = self.config.select_aggregate_resource_config(
                Expression=expr, ConfigurationAggregatorName=self.aggregator_name, Limit=10)
            for row in resp.get("Results", []):
                d = json.loads(row)
                if d.get("accountId") in EXCLUDED_ACCOUNTS:
                    continue
                c = d.get("configuration", {}) or {}
                lb_type = (c.get("type") or "").lower()
                rtype = {"network": "NLB", "application": "ALB", "gateway": "GWLB"}.get(
                    lb_type, "Load Balancer")
                scheme = c.get("scheme")
                m = ResourceMatch(
                    account_id=d.get("accountId"), region=d.get("awsRegion"),
                    resource_id=d.get("resourceName") or d.get("resourceId"),
                    resource_type=rtype,
                    workload_hint=f"{d.get('resourceName')} ({scheme})" if scheme else d.get("resourceName"),
                    description=c.get("dNSName"), source="alias-elb-dns")
                # Stash the LB ARN for the deep-trace (not serialized on the match).
                m._lb_arn = c.get("loadBalancerArn") or d.get("arn")
                matches.append(m)
        except Exception as e:  # noqa: BLE001
            return [ResourceMatch(description=f"ELB alias lookup error: {e}",
                                  workload_hint=target, source="alias-elb-dns")]
        return matches

    # ---- Deep trace: ELB -> target groups -> targets -> VPC endpoint ------
    def trace_elb_targets(self, lb_arn: str, account_id: str, region: str) -> list:
        """Live cross-account trace of an ELB's forwarding path:
        listeners -> target groups -> registered targets. For IP targets that are
        VPC-endpoint ENIs, resolve the endpoint + its service (e.g. execute-api =
        private API Gateway). Requires elasticloadbalancing:Describe* and
        ec2:DescribeNetworkInterfaces/DescribeVpcEndpoints on the spoke role.
        Returns a list of human-readable trace step dicts."""
        steps = []
        try:
            elb = self._client_for_account("elbv2", account_id, region)
            ec2 = self._client_for_account("ec2", account_id, region)
        except Exception as e:  # noqa: BLE001
            return [{"step": "trace-init", "error": str(e)}]

        tg_arns = set()
        try:
            for tg in elb.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", []):
                tg_arns.add((tg["TargetGroupArn"], tg.get("TargetGroupName"),
                             tg.get("TargetType"), tg.get("Protocol"), tg.get("Port")))
        except Exception as e:  # noqa: BLE001
            return [{"step": "describe-target-groups", "error": str(e)}]

        for tg_arn, tg_name, tg_type, proto, port in tg_arns:
            step = {"step": "target-group", "name": tg_name, "target_type": tg_type,
                    "protocol": proto, "port": port, "targets": []}
            try:
                health = elb.describe_target_health(
                    TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
            except Exception as e:  # noqa: BLE001
                step["error"] = str(e)
                steps.append(step)
                continue
            # Collect IP targets so we can look them up in one ENI call.
            ip_targets = []
            for h in health:
                tid = h.get("Target", {}).get("Id")
                state = h.get("TargetHealth", {}).get("State")
                t = {"target": tid, "health": state}
                try:
                    ipaddress.ip_address(tid)
                    ip_targets.append(tid)
                except ValueError:
                    pass
                step["targets"].append(t)
            # Resolve IP targets -> ENIs -> VPC endpoint + service.
            if ip_targets:
                self._enrich_ip_targets(ec2, ip_targets, step)
            steps.append(step)
        return steps

    def _enrich_ip_targets(self, ec2, ips: list, step: dict) -> None:
        try:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "addresses.private-ip-address", "Values": ips}]
            ).get("NetworkInterfaces", [])
        except Exception as e:  # noqa: BLE001
            step["target_eni_error"] = str(e)
            return
        endpoints = {}  # vpce-id -> set of ips
        for e in enis:
            itype = e.get("InterfaceType")
            desc = e.get("Description", "") or ""
            ip = None
            for a in e.get("PrivateIpAddresses", []):
                if a.get("PrivateIpAddress") in ips:
                    ip = a["PrivateIpAddress"]
                    break
            if itype == "vpc_endpoint" or "vpce-" in desc:
                m = re.search(r"(vpce-[0-9a-f]+)", desc)
                vpce = m.group(1) if m else "vpce-?"
                endpoints.setdefault(vpce, set()).add(ip)
        for vpce, ipset in endpoints.items():
            dest = {"via_vpc_endpoint": vpce, "target_ips": sorted(i for i in ipset if i)}
            # Describe the endpoint to get its service (the real terminus).
            try:
                ve = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce]).get("VpcEndpoints", [])
                if ve:
                    svc = ve[0].get("ServiceName", "")
                    dest["service"] = svc
                    dest["terminus"] = _classify_endpoint_service(svc)
            except Exception as e:  # noqa: BLE001
                dest["endpoint_error"] = str(e)
            step.setdefault("destinations", []).append(dest)

    # ---- Per-IP attribution: tier 1 -> 2/3 -> 4/5 -------------------------
    def attribute_ip(self, ip: str, result: ResolveResult, seen: set, source_tag: str) -> None:
        # Tier 1: exact ENI.
        enis = self.attribute_ip_eni(ip, source=source_tag)
        real = [m for m in enis if m.account_id]
        if real:
            for m in real:
                self._add_match(result, seen, m)
            return
        # Tier 2/3: containing subnet/VPC.
        net_match = self.attribute_ip_by_network(ip)
        if net_match:
            self._add_match(result, seen, net_match)
            return
        # Tier 4/5: CSAA CIDR list / generic.
        loc = classify_ip_location(ip)
        if loc:
            result.ip_locations.append(asdict(loc))

    @staticmethod
    def _add_match(result: ResolveResult, seen: set, m: ResourceMatch) -> None:
        key = (m.account_id, m.resource_id, m.private_ip)
        if key in seen:
            return
        seen.add(key)
        result.matches.append(m)

    # ---- Orchestration ----------------------------------------------------
    def resolve(self, url: str) -> ResolveResult:
        hostname = _hostname_from_url(url)
        result = ResolveResult(url=url, hostname=hostname)

        ips, dns_err = self.resolve_dns(hostname)
        result.resolved_ips = ips
        result.dns_error = dns_err

        self.lookup_route53(hostname, result)

        seen = set()

        # CloudFront by hostname alias (works even for Akamai-fronted public name).
        for m in self.attribute_cloudfront_by_alias(hostname):
            if m.account_id:
                self._add_match(result, seen, m)

        # Live-DNS IPs.
        for ip in ips:
            if _is_private_ip(ip):
                self.attribute_ip(ip, result, seen, source_tag="dns-ip")
            else:
                # Public IP: record its generic/public classification (tier 4/5),
                # since ENI/subnet attribution only applies to private IPs.
                loc = classify_ip_location(ip)
                if loc:
                    result.ip_locations.append(asdict(loc))

        # Route 53 records: A-record IPs, CloudFront, ELB alias, Akamai origin.
        for zr in result.zone_records:
            for ip in zr.get("values", []) or []:
                val = (ip or "").rstrip(".")
                if _is_private_ip(val):
                    self.attribute_ip(val, result, seen, source_tag="a-record-ip")
                elif val.endswith(CLOUDFRONT_SUFFIX):
                    for m in self.attribute_cloudfront_by_domain(val):
                        if m.account_id:
                            self._add_match(result, seen, m)
                elif any(val.endswith(s) for s in AKAMAI_SUFFIXES):
                    self._follow_akamai_origin(hostname, result, seen)
                else:
                    try:
                        ipaddress.ip_address(val)  # is it a literal public IP?
                        loc = classify_ip_location(val)
                        if loc:
                            result.ip_locations.append(asdict(loc))
                    except ValueError:
                        result.notes.append(
                            f"{val} (record value) is not an IP or known AWS/CDN target.")

            alias = (zr.get("alias_target") or "").rstrip(".")
            if not alias:
                continue
            if alias.endswith(CLOUDFRONT_SUFFIX):
                cf = self.attribute_cloudfront_by_domain(alias)
                if any(m.account_id for m in cf):
                    for m in cf:
                        if m.account_id:
                            self._add_match(result, seen, m)
                else:
                    result.notes.append(
                        f"Record aliases to CloudFront '{alias}' but no matching distribution found.")
            elif _is_elb_dns(alias):
                elbm = self.attribute_alias_target(alias)
                if elbm:
                    for m in elbm:
                        self._add_match(result, seen, m)
                        # Automatic deep-trace: follow the LB's forwarding path
                        # (target groups -> targets -> VPC endpoint/service).
                        lb_arn = getattr(m, "_lb_arn", None)
                        if lb_arn and m.account_id and m.region:
                            try:
                                chain = self.trace_elb_targets(lb_arn, m.account_id, m.region)
                                if chain:
                                    result.trace.append({
                                        "load_balancer": m.resource_id,
                                        "lb_account": m.account_id,
                                        "lb_region": m.region,
                                        "steps": chain,
                                    })
                            except Exception as e:  # noqa: BLE001
                                result.notes.append(f"Deep-trace of {m.resource_id} failed: {e}")
                else:
                    result.notes.append(
                        f"Record aliases to '{alias}' but no backing ENI found (stale ELB?).")

        if not result.matches and not result.ip_locations:
            for zr in result.zone_records:
                for v in (zr.get("values", []) or []):
                    val = (v or "").rstrip(".")
                    if any(val.endswith(s) for s in AKAMAI_SUFFIXES):
                        self._follow_akamai_origin(hostname, result, seen)
                        break

        if not result.matches and not result.ip_locations and not result.zone_records:
            result.notes.append(
                "No AWS resource/network match and no Route53 record found.")

        result.matches = [asdict(m) if not isinstance(m, dict) else m for m in result.matches]
        return result

    def _follow_akamai_origin(self, hostname: str, result: ResolveResult, seen: set) -> None:
        if hostname.startswith("origin-"):
            return
        origin_host = "origin-" + hostname
        result.notes.append(
            f"Akamai CDN detected; following CSAA origin convention -> {origin_host}")
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
                        self._add_match(result, seen, m)
            elif _is_elb_dns(alias):
                for m in self.attribute_alias_target(alias):
                    m.source = "akamai-origin-elb"
                    self._add_match(result, seen, m)
            else:
                for v in (zr.values or []):
                    vv = (v or "").rstrip(".")
                    if vv.endswith(CLOUDFRONT_SUFFIX):
                        for m in self.attribute_cloudfront_by_domain(vv):
                            if m.account_id:
                                m.source = "akamai-origin-cloudfront"
                                self._add_match(result, seen, m)
                    elif _is_private_ip(vv):
                        self.attribute_ip(vv, result, seen, source_tag="akamai-origin-ip")
            return


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python resolver.py <url> [aws_profile]")
        print("       python resolver.py --ip <ip> [aws_profile]")
        sys.exit(1)
    if sys.argv[1] == "--ip":
        ip = sys.argv[2]
        profile = sys.argv[3] if len(sys.argv) > 3 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        res = ResolveResult(url=ip, hostname=ip)
        r.attribute_ip(ip, res, set(), "manual")
        print(json.dumps({"ip": ip, "matches": res.matches, "ip_locations": res.ip_locations},
                         indent=2, default=str))
    else:
        url = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 else None
        sess = boto3.Session(profile_name=profile) if profile else None
        r = InfraResolver(session=sess)
        print(json.dumps(r.resolve(url).to_dict(), indent=2, default=str))
