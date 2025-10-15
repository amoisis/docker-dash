import os
import logging
import cloudflare
import json
from datetime import datetime
from pprint import pformat

# Module-level cache for storing tunnel information
_tunnel_cache = {}
# Module-level caches for Access resources
_access_apps_cache = {}
_access_policies_cache = {}
_idps_cache = {}
_zones_cache = {}

# Module-level client and account_id for reuse
_cf_client = None
_account_id = None

class CloudflareJSONEncoder(json.JSONEncoder):
    """A custom JSON encoder for Cloudflare API objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, 'dict'):
            return obj.dict()
        # For other types, fall back to the default encoder
        return super().default(obj)

def get_cloudflare_client():
    """
    Initializes and returns a Cloudflare API client and account ID.

    Reads credentials (CF_API_TOKEN, CF_ACCOUNT_ID) from environment variables.

    Returns:
        (cloudflare.Cloudflare, str) or (None, None): A tuple containing the
        client instance and account ID, or (None, None) if credentials are missing.
    """
    global _cf_client, _account_id
    token = os.environ.get("CF_API_TOKEN")
    account_id = os.environ.get("CF_ACCOUNT_ID")

    if not token or not account_id:
        logging.error(
            "Cloudflare credentials missing. Please set CF_API_TOKEN and CF_ACCOUNT_ID environment variables."
        )
        return None, None

    try:
        cf_client = cloudflare.Cloudflare(api_token=token)
        _cf_client = cf_client
        _account_id = account_id
        logging.info("Successfully initialized Cloudflare client.")
        return cf_client, account_id
    except Exception as e:
        logging.error(f"Failed to initialize Cloudflare client: {e}")
        return None, None


def populate_tunnel_cache(cf_client, account_id):
    """
    Fetches all Cloudflare Tunnels and their connections, populating the in-memory cache.
    """
    global _tunnel_cache
    _tunnel_cache.clear() # Clear cache before populating

    try:
        tunnels = list(cf_client.zero_trust.tunnels.list(account_id=account_id))
        logging.debug(f"Found {len(tunnels)} tunnels. Fetching their configurations...")

        for tunnel in tunnels:
            try:
                # The configuration contains the ingress rules (connections)
                config_response = cf_client.zero_trust.tunnels.cloudflared.configurations.get(account_id=account_id, tunnel_id=tunnel.id)
                
                # The actual ingress rules are in config_response.config.ingress
                ingress_rules = []
                if config_response.config and hasattr(config_response.config, 'ingress'):
                    ingress_rules = config_response.config.ingress

                _tunnel_cache[tunnel.id] = {
                    "tunnel_object": tunnel,
                    "connections": ingress_rules, # Store the list of ingress rule objects
                }
            except cloudflare.APIError as e:
                logging.error(f"Could not fetch configuration for tunnel {tunnel.name} ({tunnel.id}): {e}")
                # Still cache the tunnel, but with empty connections
                _tunnel_cache[tunnel.id] = {
                    "tunnel_object": tunnel,
                    "connections": [],
                }
    except cloudflare.APIError as e:
        logging.error(f"Cloudflare API error while listing tunnels: {e}")

def populate_access_caches(cf_client, account_id):
    """Fetches all Cloudflare Access resources and populates the in-memory caches."""
    global _access_apps_cache, _access_policies_cache, _idps_cache
    _access_apps_cache.clear()
    _access_policies_cache.clear()
    _idps_cache.clear()

    try:
        logging.info("Fetching Cloudflare Access resources...")
        apps = list(cf_client.zero_trust.access.applications.list(account_id=account_id))
        policies = list(cf_client.zero_trust.access.policies.list(account_id=account_id))
        idps = list(cf_client.zero_trust.identity_providers.list(account_id=account_id))

        _access_apps_cache = {app.domain: app for app in apps}
        _access_policies_cache = {policy.name: policy for policy in policies}
        _idps_cache = {idp.name: idp for idp in idps}

        logging.debug(f"Cached {len(_access_apps_cache)} Access Applications, {len(_access_policies_cache)} Access Policies, and {len(_idps_cache)} Identity Providers.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to fetch Cloudflare Access resources: {e}")

def populate_zones_cache(cf_client):
    """Fetches all Cloudflare zones and populates the in-memory cache."""
    global _zones_cache
    _zones_cache.clear()

    try:
        logging.info("Fetching Cloudflare DNS zones...")
        zones = list(cf_client.zones.list())
        _zones_cache = {zone.name: zone for zone in zones}
        logging.debug(f"Cached {len(_zones_cache)} DNS zones.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to fetch Cloudflare DNS zones: {e}")

def get_cached_tunnels():
    """Returns the in-memory tunnel cache."""
    return _tunnel_cache

def get_consolidated_cache():
    """Gathers all module-level caches into a single dictionary."""
    return {
        "tunnels": _tunnel_cache,
        "access_applications": _access_apps_cache,
        "access_policies": _access_policies_cache,
        "identity_providers": _idps_cache,
        "zones": _zones_cache,
    }


def initialize_and_log_tunnels():
    """
    Initializes the Cloudflare client, populates the cache, and logs existing tunnels.
    This is a convenience wrapper for application startup.
    """
    cf_client, cf_account_id = get_cloudflare_client()
    if not cf_client:
        logging.error("Could not connect to Cloudflare. Tunnel management will be disabled.")
        return

    logging.info("Populating Cloudflare tunnel cache...")
    populate_tunnel_cache(cf_client, cf_account_id)

    # Also populate Access resource caches
    populate_access_caches(cf_client, cf_account_id)

    # Also populate DNS zone cache
    populate_zones_cache(cf_client)
    
    cached_tunnels = get_cached_tunnels()
    logging.debug(f"Full tunnel cache content:\n{pformat(cached_tunnels)}")
    if cached_tunnels:
        for tunnel_id, data in cached_tunnels.items():
            tunnel = data["tunnel_object"]
            conn_count = len(data["connections"])
            logging.info(f"  - Cached Tunnel: '{tunnel.name}' (ID: {tunnel.id}) with {conn_count} connections.")
            # Log details for each connection (ingress rule)
            if conn_count > 0:
                for conn in data["connections"]:
                    # Each 'conn' is an ingress rule object with 'hostname' and 'service' attributes
                    logging.info(f"    - Connection: {conn.hostname} -> {conn.service}")
    else:
        logging.warning("No existing Cloudflare tunnels found to cache.") 

def add_or_update_ingress_rule(tunnel_name: str, new_rule: dict):
    """
    Adds or updates an ingress rule for a given tunnel, ensuring only one
    rule per hostname.

    Args:
        tunnel_name: The name of the tunnel to update.
        new_rule: A dictionary representing the new ingress rule.
    """
    global _tunnel_cache, _cf_client, _account_id
    if not _cf_client or not _account_id:
        logging.error("Cloudflare client not initialized. Cannot update ingress rule.")
        return

    target_tunnel_data = next((data for data in _tunnel_cache.values() if data["tunnel_object"].name == tunnel_name), None)

    if not target_tunnel_data:
        logging.error(f"Tunnel '{tunnel_name}' not found in cache. Cannot manage route for hostname '{new_rule.get('hostname')}'.")
        return

    new_hostname = new_rule.get("hostname")
    current_rules = target_tunnel_data["connections"]

    # Check if the exact rule already exists
    if any(r.hostname == new_hostname and r.service == new_rule.get("service") for r in current_rules):
        logging.info(f"Ingress rule '{new_hostname}' -> '{new_rule.get('service')}' already exists for tunnel '{tunnel_name}'. No update needed.")
        return

    logging.info(f"Updating ingress rules for tunnel '{tunnel_name}' to set route for '{new_hostname}'.")

    # Build the new list of rules, excluding any existing rule for the same hostname
    updated_ingress_rules = [rule.dict() for rule in current_rules if rule.hostname != new_hostname and rule.hostname is not None]
    updated_ingress_rules.append(new_rule)

    # Ensure the catch-all 404 rule is present and last
    updated_ingress_rules = [rule for rule in updated_ingress_rules if rule.get("service") != "http_status:404"]
    updated_ingress_rules.append({"service": "http_status:404"})

    tunnel_id = target_tunnel_data["tunnel_object"].id
    config_payload = {"ingress": updated_ingress_rules}

    try:
        logging.info(f"Updating tunnel '{tunnel_name}' ({tunnel_id}) with new ingress configuration.")
        config_response = _cf_client.zero_trust.tunnels.cloudflared.configurations.update(
            account_id=_account_id,
            tunnel_id=tunnel_id,
            config=config_payload
        )

        # 5. Update the local cache with the new state
        if config_response.config and hasattr(config_response.config, 'ingress'):
            _tunnel_cache[tunnel_id]["connections"] = config_response.config.ingress or []
            logging.debug(f"Successfully updated tunnel '{tunnel_name}' and refreshed cache.")
            ensure_cname_record_exists(new_hostname, tunnel_name)

    except cloudflare.APIError as e:
        logging.error(f"Failed to update tunnel configuration for '{tunnel_name}': {e}")

def ensure_cname_record_exists(hostname: str, tunnel_name: str):
    """
    Ensures a CNAME record exists for a given hostname pointing to a tunnel.
    """
    global _cf_client, _zones_cache, _tunnel_cache
    if not _cf_client:
        logging.error("Cloudflare client not initialized. Cannot create CNAME record.")
        return

    # Find the zone for the hostname
    zone_name = '.'.join(hostname.split('.')[-2:])
    zone = _zones_cache.get(zone_name)
    if not zone:
        logging.error(f"Zone '{zone_name}' not found for hostname '{hostname}'. Cannot create CNAME record.")
        return

    # Find the tunnel to get its CNAME
    target_tunnel_data = next((data for data in _tunnel_cache.values() if data["tunnel_object"].name == tunnel_name), None)
    if not target_tunnel_data:
        logging.error(f"Tunnel '{tunnel_name}' not found. Cannot create CNAME record.")
        return

    tunnel_cname = f"{target_tunnel_data['tunnel_object'].id}.cfargotunnel.com"

    try:
        records = _cf_client.dns.records.list(zone_id=zone.id, name=hostname)
        if records:
            logging.info(f"CNAME record for '{hostname}' already exists.")
            return

        logging.info(f"Creating CNAME record for '{hostname}' pointing to '{tunnel_cname}'.")
        _cf_client.dns.records.create(
            zone_id=zone.id,
            type="CNAME",
            name=hostname,
            content=tunnel_cname,
            proxied=True
        )
        logging.info(f"Successfully created CNAME record for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to create CNAME record for '{hostname}': {e}")

def remove_cname_record(hostname: str):
    """
    Removes a CNAME record for a given hostname.
    """
    global _cf_client, _zones_cache
    if not _cf_client:
        logging.error("Cloudflare client not initialized. Cannot remove CNAME record.")
        return

    # Find the zone for the hostname
    zone_name = '.'.join(hostname.split('.')[-2:])
    zone = _zones_cache.get(zone_name)
    if not zone:
        logging.warning(f"Zone '{zone_name}' not found for hostname '{hostname}'. Cannot remove CNAME record.")
        return

    try:
        # Find the DNS record ID
        records = _cf_client.dns.records.list(zone_id=zone.id, name=hostname)
        if not records:
            logging.info(f"CNAME record for '{hostname}' not found. No action needed.")
            return

        record_id = records[0].id
        logging.info(f"Removing CNAME record for '{hostname}' (ID: {record_id}).")
        _cf_client.dns.records.delete(zone_id=zone.id, dns_record_id=record_id)
        logging.info(f"Successfully removed CNAME record for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to remove CNAME record for '{hostname}': {e}")

def add_or_update_access_application(hostname: str, access_config: dict):
    """
    Creates or updates a Cloudflare Access Application for a given hostname.

    Args:
        hostname: The domain of the application.
        access_config: A dictionary of access configuration parsed from labels.
    """
    global _access_apps_cache, _access_policies_cache, _idps_cache, _cf_client, _account_id
    if not _cf_client or not _account_id:
        logging.error("Cloudflare client not initialized. Cannot manage Access Application.")
        return

    # 1. Translate policy names to UUIDs
    policy_names = [p.strip() for p in access_config.get("policy", "").split(',') if p.strip()]
    policy_uuids = []
    for name in policy_names:
        if name in _access_policies_cache:
            policy_uuids.append(_access_policies_cache[name].id)
        else:
            logging.error(f"Access Policy '{name}' not found in cache. Cannot apply to application '{hostname}'.")
            logging.debug(f"Available policies in cache: {list(_access_policies_cache.keys())}")
            return

    if not policy_uuids:
        logging.warning(f"No valid Access Policies found for application '{hostname}'. Skipping Access setup.")
        return

    # 2. Translate IdP names to UUIDs
    idp_names = [idp.strip() for idp in access_config.get("loginmethods", "").split(',') if idp.strip()]
    allowed_idps = []
    for name in idp_names:
        if name in _idps_cache:
            allowed_idps.append(_idps_cache[name].id)
        else:
            logging.warning(f"Identity Provider '{name}' not found in cache for application '{hostname}'.")

    # 3. Construct the API payload
    payload = {
        "domain": hostname,
        "type": "self_hosted"
    }
    if allowed_idps:
        payload["allowed_idps"] = allowed_idps   
        # Explicitly disable "accept all" when specific IdPs are provided.
        payload["enable_binding_cookie"] = False
    if "icon" in access_config:
        payload["logo_url"] = access_config["icon"]
    
    # Set instant auth if requested and valid (only one IdP)
    if access_config.get("instantauth") == "true" and len(allowed_idps) == 1:
        payload["auto_redirect_to_identity"] = True
    else:
        # Explicitly set to false if not meeting conditions, to handle updates correctly
        payload["auto_redirect_to_identity"] = False

    # 4. Check if app exists and create or update
    existing_app = _access_apps_cache.get(hostname)

    # Separate logic for create vs update as API requirements differ
    if existing_app:
        try:
            logging.info(f"Updating existing Access Application for '{hostname}'...")
            # For updates, policies are part of the main payload.
            payload["policies"] = [{"id": uid, "precedence": i + 1} for i, uid in enumerate(policy_uuids)]
            response = _cf_client.zero_trust.access.applications.update(
                app_id=existing_app.id,
                account_id=_account_id,
                **payload
            )
            _access_apps_cache[hostname] = response # Update cache
            logging.info(f"Successfully updated Access Application for '{hostname}'.")
        except cloudflare.APIError as e:
            logging.error(f"Failed to update Access Application for '{hostname}': {e}")
    else:
        try:
            payload["policies"] = [{"id": uid, "precedence": i + 1} for i, uid in enumerate(policy_uuids)]
            logging.info(f"Creating new Access Application for '{hostname}'...")
            response = _cf_client.zero_trust.access.applications.create(
                account_id=_account_id,
                **payload
            )
            _access_apps_cache[hostname] = response # Update cache
            logging.info(f"Successfully created Access Application for '{hostname}'.")
        except cloudflare.APIError as e:
            logging.error(f"Failed to create Access Application for '{hostname}': {e}")

def remove_ingress_rule(tunnel_name: str, hostname: str):
    """
    Removes an ingress rule for a given tunnel by hostname.

    Args:
        tunnel_name: The name of the tunnel to update.
        hostname: The hostname of the ingress rule to remove.
    """
    global _tunnel_cache, _cf_client, _account_id
    if not _cf_client or not _account_id:
        logging.error("Cloudflare client not initialized. Cannot remove ingress rule.")
        return

    target_tunnel_data = None
    for data in _tunnel_cache.values():
        if data["tunnel_object"].name == tunnel_name:
            target_tunnel_data = data
            break

    if not target_tunnel_data:
        logging.error(f"Tunnel '{tunnel_name}' not found in cache. Cannot remove route for hostname '{hostname}'.")
        return

    # Find the rule to remove
    rule_to_remove = None
    for existing_rule in target_tunnel_data["connections"]:
        if existing_rule.hostname == hostname:
            rule_to_remove = existing_rule
            break
    
    if not rule_to_remove:
        logging.info(f"Ingress rule for hostname '{hostname}' not found in tunnel '{tunnel_name}'. No action needed.")
        return

    logging.info(f"Removing ingress rule for '{hostname}' from tunnel '{tunnel_name}'.")

    # Construct the new list of ingress rules
    updated_ingress_rules = [
        rule.dict() for rule in target_tunnel_data["connections"] if rule.hostname != hostname
    ]

    # Ensure the catch-all 404 rule is still last
    updated_ingress_rules = [rule for rule in updated_ingress_rules if rule.get("service") != "http_status:404"]
    updated_ingress_rules.append({"service": "http_status:404"})

    tunnel_id = target_tunnel_data["tunnel_object"].id
    config_payload = {"ingress": updated_ingress_rules}

    try:
        logging.info(f"Updating tunnel '{tunnel_name}' ({tunnel_id}) to remove ingress for '{hostname}'.")
        config_response = _cf_client.zero_trust.tunnels.cloudflared.configurations.update(
            account_id=_account_id,
            tunnel_id=tunnel_id,
            config=config_payload
        )

        if config_response.config and hasattr(config_response.config, 'ingress'):
            _tunnel_cache[tunnel_id]["connections"] = config_response.config.ingress or []
            logging.debug(f"Successfully updated tunnel '{tunnel_name}' and refreshed cache after removing rule.")
            remove_cname_record(hostname)

    except cloudflare.APIError as e:
        logging.error(f"Failed to update tunnel configuration for '{tunnel_name}' to remove rule: {e}")

def remove_access_application(hostname: str):
    """
    Deletes a Cloudflare Access Application by its hostname.

    Args:
        hostname: The domain of the application to delete.
    """
    global _access_apps_cache, _cf_client, _account_id
    if not _cf_client or not _account_id:
        logging.error("Cloudflare client not initialized. Cannot remove Access Application.")
        return

    existing_app = _access_apps_cache.get(hostname)
    if not existing_app:
        logging.info(f"Access Application for '{hostname}' not found in cache. No action needed.")
        return

    logging.info(f"Removing Access Application for '{hostname}' (ID: {existing_app.id}).")

    try:
        _cf_client.zero_trust.access.applications.delete(
            app_id=existing_app.id,
            account_id=_account_id
        )
        # Remove from cache
        if hostname in _access_apps_cache:
            del _access_apps_cache[hostname]
        logging.info(f"Successfully deleted Access Application for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to delete Access Application for '{hostname}': {e}")