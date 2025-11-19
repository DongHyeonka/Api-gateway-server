package com.synapse.api_gateway_server.filter;

import com.synapse.synapse_domain_model.SubscriptionTier;

public record AuthenticatedUser(
    String userId,
    String workspaceId,
    SubscriptionTier tier
) {
}
