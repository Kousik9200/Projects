# Zero Trust Access Policy — Open Policy Agent (OPA)
# Author: Kousik Gunasekaran
# All traffic denied by default. Explicit allow only.

package zerotrust.authz

import future.keywords.if
import future.keywords.in

default allow := false

# Allow if all conditions pass
allow if {
    identity_verified
    device_compliant
    request_in_allowed_scope
    not anomalous_behavior
}

# Identity must be verified via mTLS certificate
identity_verified if {
    input.certificate.valid == true
    input.certificate.issuer == "CN=ZeroTrustLab CA"
    not certificate_expired
}

certificate_expired if {
    input.certificate.expiry < time.now_ns()
}

# Device must pass compliance check
device_compliant if {
    input.device.os_patched == true
    input.device.antivirus_active == true
    input.device.disk_encrypted == true
}

# Request must be within allowed service scope
request_in_allowed_scope if {
    allowed_paths[input.service][_] == input.requested_path
}

allowed_paths := {
    "dev-service": ["/api/v1/dev", "/health"],
    "prod-service": ["/api/v1/prod", "/health"],
    "mgmt-service": ["/admin", "/metrics"],
}

# Flag anomalous after-hours access to sensitive segments
anomalous_behavior if {
    input.requested_path in ["/admin", "/api/v1/prod"]
    hour := time.clock(time.now_ns())[0]
    hour < 7
}

anomalous_behavior if {
    input.requested_path in ["/admin", "/api/v1/prod"]
    hour := time.clock(time.now_ns())[0]
    hour > 21
}

# Deny cross-VLAN access unless explicitly permitted
deny_cross_vlan if {
    input.source_vlan != input.target_vlan
    not cross_vlan_allowed[input.source_vlan][input.target_vlan]
}

cross_vlan_allowed := {
    "VLAN_DEV": {"VLAN_MGMT": true},
    "VLAN_PROD": {"VLAN_MGMT": true},
}
