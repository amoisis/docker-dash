import os
import logging
import cloudflare
import json
import time
import threading
from datetime import datetime
from pprint import pformat
from functools import wraps


class CloudflareManager:
    """Manages Cloudflare API interactions and caches with encapsulated state."""
    
    def __init__(self, cache_refresh_interval=None):
        # Caches for Cloudflare resources
        self.tunnel_cache = {}
        self.access_apps_cache = {}
        self.access_policies_cache = {}
        self.idps_cache = {}
        self.zones_cache = {}
        
        # Client state
        self.cf_client = None
        self.account_id = None
        
        # Cache refresh control
        self.cache_refresh_thread = None
        self.cache_refresh_interval = cache_refresh_interval or int(os.environ.get("CACHE_REFRESH_INTERVAL", "300"))
        self.stop_refresh = False


# Global manager instance for backward compatibility
_manager = CloudflareManager()

class CloudflareJSONEncoder(json.JSONEncoder):
    """A custom JSON encoder for Cloudflare API objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, 'dict'):
            return obj.dict()
        # For other types, fall back to the default encoder
        return super().default(obj)

def retry_on_api_error(max_retries=3, initial_delay=1, backoff_factor=2):
    """Decorator to retry Cloudflare API calls with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except cloudflare.APIError as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        logging.warning(
                            f"Cloudflare API error in {func.__name__} (attempt {attempt + 1}/{max_retries}): {e}. "
                            f"Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        logging.error(
                            f"Cloudflare API error in {func.__name__} after {max_retries} attempts: {e}"
                        )
                except Exception as e:
                    # Don't retry on non-API errors
                    logging.error(f"Unexpected error in {func.__name__}: {e}")
                    raise
            
            # If we exhausted retries, raise the last exception
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator


# ===========================
# Input Validation Functions
# ===========================

class ValidationError(ValueError):
    """Custom exception for input validation errors."""
    pass


def validate_hostname(hostname: str) -> None:
    """
    Validates that a hostname is DNS-compliant.
    
    Args:
        hostname: The hostname to validate
        
    Raises:
        ValidationError: If hostname is invalid
    """
    if not hostname or not isinstance(hostname, str):
        raise ValidationError("Hostname must be a non-empty string")
    
    hostname = hostname.strip()
    
    # Check total length (DNS limit is 253 characters)
    if len(hostname) > 253:
        raise ValidationError(f"Hostname too long: {len(hostname)} characters (max 253)")
    
    # Require at least one dot (FQDN with domain and TLD)
    if '.' not in hostname.replace('*.', ''):
        raise ValidationError(f"Hostname must include domain and TLD: '{hostname}'")
    
    # Check for valid characters and structure
    import re
    # Allow alphanumeric, hyphens, dots, and wildcards at start
    hostname_pattern = re.compile(
        r'^(\*\.)?'  # Optional wildcard subdomain
        r'([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # Subdomains
        r'([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$'  # TLD
    )
    
    if not hostname_pattern.match(hostname):
        raise ValidationError(
            f"Invalid hostname format: '{hostname}'. "
            "Must contain only alphanumeric characters, hyphens, and dots. "
            "Labels cannot start or end with hyphens."
        )
    
    # Check individual label lengths (each part between dots)
    labels = hostname.replace('*.', '').split('.')
    for label in labels:
        if len(label) > 63:
            raise ValidationError(f"Hostname label too long: '{label}' (max 63 characters)")
        if not label:
            raise ValidationError("Hostname cannot have empty labels (consecutive dots)")


def validate_tunnel_name(tunnel_name: str) -> None:
    """
    Validates that a tunnel name follows Cloudflare's naming conventions.
    
    Args:
        tunnel_name: The tunnel name to validate
        
    Raises:
        ValidationError: If tunnel name is invalid
    """
    if not tunnel_name or not isinstance(tunnel_name, str):
        raise ValidationError("Tunnel name must be a non-empty string")
    
    tunnel_name = tunnel_name.strip()
    
    # Check length (reasonable limit)
    if len(tunnel_name) > 100:
        raise ValidationError(f"Tunnel name too long: {len(tunnel_name)} characters (max 100)")
    
    if len(tunnel_name) < 1:
        raise ValidationError("Tunnel name cannot be empty")
    
    # Allow alphanumeric, hyphens, underscores
    import re
    tunnel_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    if not tunnel_pattern.match(tunnel_name):
        raise ValidationError(
            f"Invalid tunnel name: '{tunnel_name}'. "
            "Must contain only alphanumeric characters, hyphens, and underscores."
        )


def validate_service_url(service: str) -> None:
    """
    Validates that a service URL/target is properly formatted.
    
    Args:
        service: The service URL to validate (e.g., 'http://container:8080')
        
    Raises:
        ValidationError: If service URL is invalid
    """
    if not service or not isinstance(service, str):
        raise ValidationError("Service must be a non-empty string")
    
    service = service.strip()
    
    # Allow special status codes
    if service.startswith('http_status:'):
        try:
            status_code = int(service.split(':')[1])
            if status_code < 100 or status_code > 599:
                raise ValidationError(f"Invalid HTTP status code: {status_code}")
            return
        except (ValueError, IndexError):
            raise ValidationError(f"Invalid http_status format: '{service}'")
    
    # Validate as URL
    import re
    # Basic URL validation (protocol + host + optional port + path)
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # hostname
        r'(:[0-9]{1,5})?'  # optional port
        r'(/.*)?$'  # optional path
    )
    
    if not url_pattern.match(service):
        raise ValidationError(
            f"Invalid service URL: '{service}'. "
            "Must be a valid http:// or https:// URL or 'http_status:XXX'"
        )


def get_cloudflare_client(manager=None):
    """
    Initializes and returns a Cloudflare API client and account ID.

    Reads credentials (CF_API_TOKEN, CF_ACCOUNT_ID) from environment variables.

    Args:
        manager: Optional CloudflareManager instance. Uses global if None.

    Returns:
        (cloudflare.Cloudflare, str) or (None, None): A tuple containing the
        client instance and account ID, or (None, None) if credentials are missing.
    """
    if manager is None:
        manager = _manager
        
    token = os.environ.get("CF_API_TOKEN")
    account_id = os.environ.get("CF_ACCOUNT_ID")

    if not token or not account_id:
        logging.error(
            "Cloudflare credentials missing. Please set CF_API_TOKEN and CF_ACCOUNT_ID environment variables."
        )
        return None, None

    try:
        cf_client = cloudflare.Cloudflare(api_token=token)
        manager.cf_client = cf_client
        manager.account_id = account_id
        logging.info("Successfully initialized Cloudflare client.")
        return cf_client, account_id
    except Exception as e:
        logging.error(f"Failed to initialize Cloudflare client: {e}")
        return None, None


def populate_tunnel_cache(cf_client, account_id, manager=None):
    """
    Fetches all Cloudflare Tunnels and their connections, populating the in-memory cache.
    
    Args:
        cf_client: Cloudflare client instance
        account_id: Cloudflare account ID
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    manager.tunnel_cache.clear() # Clear cache before populating
    
    failed_tunnels = []

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

                manager.tunnel_cache[tunnel.id] = {
                    "tunnel_object": tunnel,
                    "connections": ingress_rules, # Store the list of ingress rule objects
                }
                logging.debug(f"Successfully cached tunnel '{tunnel.name}' with {len(ingress_rules)} connections.")
            except cloudflare.APIError as e:
                logging.error(f"Could not fetch configuration for tunnel {tunnel.name} ({tunnel.id}): {e}")
                # Still cache the tunnel, but with empty connections and mark as failed
                manager.tunnel_cache[tunnel.id] = {
                    "tunnel_object": tunnel,
                    "connections": [],
                }
                failed_tunnels.append(tunnel.name)
        
        if failed_tunnels:
            logging.warning(
                f"Cache population incomplete. Failed to fetch configs for {len(failed_tunnels)} tunnel(s): {', '.join(failed_tunnels)}. "
                "These tunnels will have empty connection lists which may cause incorrect behavior."
            )
    except cloudflare.APIError as e:
        logging.error(f"Cloudflare API error while listing tunnels: {e}")
        logging.error("Tunnel cache population failed completely. Tunnel operations may not work correctly.")
        raise

def populate_access_caches(cf_client, account_id, manager=None):
    """Fetches all Cloudflare Access resources and populates the in-memory caches.
    
    Args:
        cf_client: Cloudflare client instance
        account_id: Cloudflare account ID
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    manager.access_apps_cache.clear()
    manager.access_policies_cache.clear()
    manager.idps_cache.clear()

    try:
        logging.info("Fetching Cloudflare Access resources...")
        apps = list(cf_client.zero_trust.access.applications.list(account_id=account_id))
        policies = list(cf_client.zero_trust.access.policies.list(account_id=account_id))
        idps = list(cf_client.zero_trust.identity_providers.list(account_id=account_id))

        manager.access_apps_cache = {app.domain: app for app in apps}
        manager.access_policies_cache = {policy.name: policy for policy in policies}
        manager.idps_cache = {idp.name: idp for idp in idps}

        logging.info(f"Cached {len(manager.access_apps_cache)} Access Apps, "
                     f"{len(manager.access_policies_cache)} Policies, and {len(manager.idps_cache)} IDPs.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to populate Access caches: {e}")

def populate_zones_cache(cf_client, manager=None):
    """Fetches all Cloudflare zones and populates the in-memory cache.
    
    Args:
        cf_client: Cloudflare client instance
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    manager.zones_cache.clear()

    try:
        logging.info("Fetching Cloudflare DNS zones...")
        zones = list(cf_client.zones.list())
        manager.zones_cache = {zone.name: zone for zone in zones}
        logging.debug(f"Cached {len(manager.zones_cache)} DNS zones.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to fetch Cloudflare DNS zones: {e}")
        logging.error("Zone cache population failed. DNS record operations may not work correctly.")
        raise

def get_cached_tunnels(manager=None):
    """Returns the in-memory tunnel cache.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
    return manager.tunnel_cache

def get_consolidated_cache(manager=None):
    """Gathers all caches into a single dictionary.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
    return {
        "tunnels": manager.tunnel_cache,
        "access_applications": manager.access_apps_cache,
        "access_policies": manager.access_policies_cache,
        "identity_providers": manager.idps_cache,
        "zones": manager.zones_cache,
    }


def refresh_all_caches(manager=None):
    """Refreshes all Cloudflare caches.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    if not manager.cf_client or not manager.account_id:
        logging.warning("Cloudflare client not initialized. Skipping cache refresh.")
        return
    
    try:
        logging.info("Refreshing Cloudflare caches...")
        populate_tunnel_cache(manager.cf_client, manager.account_id, manager)
        populate_access_caches(manager.cf_client, manager.account_id, manager)
        populate_zones_cache(manager.cf_client, manager)
        logging.info("Cache refresh completed successfully.")
    except Exception as e:
        logging.error(f"Error during cache refresh: {e}")

def periodic_cache_refresh(manager=None):
    """Background thread function to periodically refresh caches.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    while not manager.stop_refresh:
        # Sleep first (initial cache is populated at startup)
        for _ in range(manager.cache_refresh_interval):
            if manager.stop_refresh:
                return
            time.sleep(1)
        
        if not manager.stop_refresh:
            refresh_all_caches(manager)

def start_cache_refresh_thread(manager=None):
    """Starts the periodic cache refresh in a background thread.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    if manager.cache_refresh_interval <= 0:
        logging.info("Cache refresh disabled (CACHE_REFRESH_INTERVAL <= 0).")
        return
    
    logging.info(f"Starting periodic cache refresh (interval: {manager.cache_refresh_interval}s)...")
    manager.cache_refresh_thread = threading.Thread(target=periodic_cache_refresh, args=(manager,), daemon=True)
    manager.cache_refresh_thread.start()

def stop_cache_refresh_thread(manager=None):
    """Stops the periodic cache refresh thread.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    if manager.cache_refresh_thread and manager.cache_refresh_thread.is_alive():
        logging.info("Stopping cache refresh thread...")
        manager.stop_refresh = True
        manager.cache_refresh_thread.join(timeout=5)

def initialize_and_log_tunnels(manager=None):
    """
    Initializes the Cloudflare client, populates the cache, and logs existing tunnels.
    This is a convenience wrapper for application startup.
    
    Args:
        manager: Optional CloudflareManager instance. Uses global if None.
    """
    if manager is None:
        manager = _manager
        
    cf_client, cf_account_id = get_cloudflare_client(manager)
    if not cf_client:
        logging.error("Could not connect to Cloudflare. Tunnel management will be disabled.")
        return

    logging.info("Populating Cloudflare caches...")
    try:
        populate_tunnel_cache(cf_client, cf_account_id, manager)
        populate_access_caches(cf_client, cf_account_id, manager)
        populate_zones_cache(cf_client, manager)
    except Exception as e:
        logging.critical(f"Critical error during initial cache population: {e}")
        logging.critical("Application may not function correctly. Please check Cloudflare credentials and API access.")
        # Don't exit - let the app continue but warn heavily
    
    cached_tunnels = get_cached_tunnels(manager)
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
    
    # Start periodic cache refresh
    start_cache_refresh_thread(manager) 

def add_or_update_ingress_rule(tunnel_name: str, new_rule: dict, manager=None):
    """
    Adds or updates an ingress rule for a given tunnel, ensuring only one
    rule per hostname.

    Args:
        tunnel_name: The name of the tunnel to update.
        new_rule: A dictionary representing the new ingress rule.
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If tunnel_name, hostname, or service are invalid.
    """
    if manager is None:
        manager = _manager
    
    # Validate inputs
    try:
        validate_tunnel_name(tunnel_name)
        if 'hostname' in new_rule:
            validate_hostname(new_rule['hostname'])
        if 'service' in new_rule:
            validate_service_url(new_rule['service'])
    except ValidationError as e:
        logging.error(f"Validation error in add_or_update_ingress_rule: {e}")
        return
        
    if not manager.cf_client or not manager.account_id:
        logging.error("Cloudflare client not initialized. Cannot update ingress rule.")
        return

    target_tunnel_data = next((data for data in manager.tunnel_cache.values() if data["tunnel_object"].name == tunnel_name), None)

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
        config_response = retry_on_api_error()(
            lambda: manager.cf_client.zero_trust.tunnels.cloudflared.configurations.update(
                account_id=manager.account_id,
                tunnel_id=tunnel_id,
                config=config_payload
            )
        )()

        # 5. Update the local cache with the new state
        if config_response.config and hasattr(config_response.config, 'ingress'):
            manager.tunnel_cache[tunnel_id]["connections"] = config_response.config.ingress or []
            logging.debug(f"Successfully updated tunnel '{tunnel_name}' and refreshed cache.")
            ensure_cname_record_exists(new_hostname, tunnel_name, manager)

    except cloudflare.APIError as e:
        logging.error(f"Failed to update tunnel configuration for '{tunnel_name}': {e}")

def ensure_cname_record_exists(hostname: str, tunnel_name: str, manager=None):
    """
    Ensures a CNAME record exists for a given hostname pointing to a tunnel.
    
    Args:
        hostname: The hostname for the CNAME record
        tunnel_name: The name of the tunnel
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If hostname or tunnel_name are invalid.
    """
    if manager is None:
        manager = _manager
    
    # Validate inputs
    try:
        validate_hostname(hostname)
        validate_tunnel_name(tunnel_name)
    except ValidationError as e:
        logging.error(f"Validation error in ensure_cname_record_exists: {e}")
        return
        
    if not manager.cf_client:
        logging.error("Cloudflare client not initialized. Cannot create CNAME record.")
        return

    # Find the zone for the hostname by finding longest matching suffix
    # This handles multi-part TLDs like .co.uk correctly
    zone = None
    zone_name = None
    parts = hostname.split('.')
    for i in range(len(parts) - 1):
        potential_zone = '.'.join(parts[i:])
        if potential_zone in manager.zones_cache:
            zone = manager.zones_cache[potential_zone]
            zone_name = potential_zone
            break
    
    if not zone:
        logging.error(f"No matching zone found in cache for hostname '{hostname}'. Cannot create CNAME record.")
        logging.debug(f"Available zones: {list(manager.zones_cache.keys())}")
        return

    # Find the tunnel to get its CNAME
    target_tunnel_data = next((data for data in manager.tunnel_cache.values() if data["tunnel_object"].name == tunnel_name), None)
    if not target_tunnel_data:
        logging.error(f"Tunnel '{tunnel_name}' not found. Cannot create CNAME record.")
        return

    tunnel_cname = f"{target_tunnel_data['tunnel_object'].id}.cfargotunnel.com"

    try:
        records = retry_on_api_error()(
            lambda: manager.cf_client.dns.records.list(zone_id=zone.id, name=hostname)
        )()
        if records:
            logging.info(f"CNAME record for '{hostname}' already exists.")
            return

        logging.info(f"Creating CNAME record for '{hostname}' pointing to '{tunnel_cname}'.")
        retry_on_api_error()(
            lambda: manager.cf_client.dns.records.create(
                zone_id=zone.id,
                type="CNAME",
                name=hostname,
                content=tunnel_cname,
                proxied=True
            )
        )()
        logging.info(f"Successfully created CNAME record for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to create CNAME record for '{hostname}': {e}")

def remove_cname_record(hostname: str, manager=None):
    """
    Removes all CNAME records for a given hostname.
    
    Args:
        hostname: The hostname for the CNAME records to remove
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If hostname is invalid.
    """
    if manager is None:
        manager = _manager
    
    # Validate inputs
    try:
        validate_hostname(hostname)
    except ValidationError as e:
        logging.error(f"Validation error in remove_cname_record: {e}")
        return
        
    if not manager.cf_client:
        logging.error("Cloudflare client not initialized. Cannot remove CNAME record.")
        return

    # Find the zone for the hostname by finding longest matching suffix
    zone = None
    zone_name = None
    parts = hostname.split('.')
    for i in range(len(parts) - 1):
        potential_zone = '.'.join(parts[i:])
        if potential_zone in manager.zones_cache:
            zone = manager.zones_cache[potential_zone]
            zone_name = potential_zone
            break
    
    if not zone:
        logging.warning(f"No matching zone found for hostname '{hostname}'. Cannot remove CNAME record.")
        return

    try:
        # Find all DNS records for this hostname
        records = retry_on_api_error()(
            lambda: manager.cf_client.dns.records.list(zone_id=zone.id, name=hostname)
        )()
        if not records:
            logging.info(f"CNAME record for '{hostname}' not found. No action needed.")
            return

        # Remove all matching records (handles duplicates)
        for record in records:
            logging.info(f"Removing CNAME record for '{hostname}' (ID: {record.id}).")
            retry_on_api_error()(
                lambda: manager.cf_client.dns.records.delete(zone_id=zone.id, dns_record_id=record.id)
            )()
        
        logging.info(f"Successfully removed {len(records)} CNAME record(s) for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to remove CNAME record for '{hostname}': {e}")

def add_or_update_access_application(hostname: str, access_config: dict, manager=None):
    """
    Creates or updates a Cloudflare Access Application for a given hostname.

    Args:
        hostname: The domain of the application.
        access_config: A dictionary of access configuration parsed from labels.
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If hostname is invalid.
    """
    # Validate inputs
    try:
        validate_hostname(hostname)
    except ValidationError as e:
        logging.error(f"Validation error in add_or_update_access_application: {e}")
        return
    if manager is None:
        manager = _manager
        
    if not manager.cf_client or not manager.account_id:
        logging.error("Cloudflare client not initialized. Cannot manage Access Application.")
        return

    # 1. Translate policy names to UUIDs
    policy_names = [p.strip() for p in access_config.get("policy", "").split(',') if p.strip()]
    policy_uuids = []
    for name in policy_names:
        if name in manager.access_policies_cache:
            policy_uuids.append(manager.access_policies_cache[name].id)
        else:
            logging.error(f"Access Policy '{name}' not found in cache. Cannot apply to application '{hostname}'.")
            logging.debug(f"Available policies in cache: {list(manager.access_policies_cache.keys())}")
            return

    if not policy_uuids:
        logging.warning(f"No valid Access Policies found for application '{hostname}'. Skipping Access setup.")
        return

    # 2. Translate IdP names to UUIDs
    idp_names = [idp.strip() for idp in access_config.get("loginmethods", "").split(',') if idp.strip()]
    allowed_idps = []
    for name in idp_names:
        if name in manager.idps_cache:
            allowed_idps.append(manager.idps_cache[name].id)
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
    existing_app = manager.access_apps_cache.get(hostname)

    # Separate logic for create vs update as API requirements differ
    if existing_app:
        try:
            logging.info(f"Updating existing Access Application for '{hostname}'...")
            # For updates, policies are part of the main payload.
            payload["policies"] = [{"id": uid, "precedence": i + 1} for i, uid in enumerate(policy_uuids)]
            response = retry_on_api_error()(
                lambda: manager.cf_client.zero_trust.access.applications.update(
                    app_id=existing_app.id,
                    account_id=manager.account_id,
                    **payload
                )
            )()
            manager.access_apps_cache[hostname] = response # Update cache
            logging.info(f"Successfully updated Access Application for '{hostname}'.")
        except cloudflare.APIError as e:
            logging.error(f"Failed to update Access Application for '{hostname}': {e}")
    else:
        try:
            payload["policies"] = [{"id": uid, "precedence": i + 1} for i, uid in enumerate(policy_uuids)]
            logging.info(f"Creating new Access Application for '{hostname}'...")
            response = retry_on_api_error()(
                lambda: manager.cf_client.zero_trust.access.applications.create(
                    account_id=manager.account_id,
                    **payload
                )
            )()
            manager.access_apps_cache[hostname] = response # Update cache
            logging.info(f"Successfully created Access Application for '{hostname}'.")
        except cloudflare.APIError as e:
            logging.error(f"Failed to create Access Application for '{hostname}': {e}")

def remove_ingress_rule(tunnel_name: str, hostname: str, manager=None):
    """
    Removes an ingress rule for a given tunnel by hostname.

    Args:
        tunnel_name: The name of the tunnel to update.
        hostname: The hostname of the ingress rule to remove.
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If tunnel_name or hostname are invalid.
    """
    if manager is None:
        manager = _manager
    
    # Validate inputs
    try:
        validate_tunnel_name(tunnel_name)
        validate_hostname(hostname)
    except ValidationError as e:
        logging.error(f"Validation error in remove_ingress_rule: {e}")
        return
        
    if not manager.cf_client or not manager.account_id:
        logging.error("Cloudflare client not initialized. Cannot remove ingress rule.")
        return

    target_tunnel_data = None
    for data in manager.tunnel_cache.values():
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
        config_response = retry_on_api_error()(
            lambda: manager.cf_client.zero_trust.tunnels.cloudflared.configurations.update(
                account_id=manager.account_id,
                tunnel_id=tunnel_id,
                config=config_payload
            )
        )()

        if config_response.config and hasattr(config_response.config, 'ingress'):
            manager.tunnel_cache[tunnel_id]["connections"] = config_response.config.ingress or []
            logging.debug(f"Successfully updated tunnel '{tunnel_name}' and refreshed cache after removing rule.")
            remove_cname_record(hostname)

    except cloudflare.APIError as e:
        logging.error(f"Failed to update tunnel configuration for '{tunnel_name}' to remove rule: {e}")

def remove_access_application(hostname: str, manager=None):
    """
    Deletes a Cloudflare Access Application by its hostname.

    Args:
        hostname: The domain of the application to delete.
        manager: Optional CloudflareManager instance. Uses global if None.
        
    Raises:
        ValidationError: If hostname is invalid.
    """
    if manager is None:
        manager = _manager
    
    # Validate inputs
    try:
        validate_hostname(hostname)
    except ValidationError as e:
        logging.error(f"Validation error in remove_access_application: {e}")
        return
        
    if not manager.cf_client or not manager.account_id:
        logging.error("Cloudflare client not initialized. Cannot remove Access Application.")
        return

    existing_app = manager.access_apps_cache.get(hostname)
    if not existing_app:
        logging.info(f"Access Application for '{hostname}' not found in cache. No action needed.")
        return

    logging.info(f"Removing Access Application for '{hostname}' (ID: {existing_app.id}).")

    try:
        retry_on_api_error()(
            lambda: manager.cf_client.zero_trust.access.applications.delete(
                app_id=existing_app.id,
                account_id=manager.account_id
            )
        )()
        # Remove from cache
        if hostname in manager.access_apps_cache:
            del manager.access_apps_cache[hostname]
        logging.info(f"Successfully deleted Access Application for '{hostname}'.")
    except cloudflare.APIError as e:
        logging.error(f"Failed to delete Access Application for '{hostname}': {e}")