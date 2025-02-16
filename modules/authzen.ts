import { HttpProblems, ZuploContext, ZuploRequest, environment } from "@zuplo/runtime"

const pdps = {
  "Aserto": "https://authzen-gateway-proxy.demo.aserto.com",
  "Axiomatics": "https://pdp.alfa.guide",
  "Cerbos": "https://authzen-proxy-demo.cerbos.dev",
  "PlainID": "https://authzeninteropt.se-plainid.com"
}

export default async function policy(
  request: ZuploRequest,
  context: ZuploContext,
) {

  if (!request.user) {
    context.log.error(
      "User is not authenticated. An authentication policy must come before the authorization policy.",
    );
    return HttpProblems.unauthorized(request, context);
  }

  const authzenRequest = JSON.stringify({
    "subject": {
      "type": "user",
      "id": request.user.sub
    },
    "resource": {
      "type": "route",
      "id": context.route.path
    },
    "action": {
      "name": request.method,
    },
  })

  const gatewayPdp = request.headers.get("X_AUTHZEN_GATEWAY_PDP")
  if (!gatewayPdp) {
    context.log.error("GATEWAY PDP URL is missing in the request headers.");
    return HttpProblems.forbidden(request, context);
  }
  const pdpUrl = pdps[gatewayPdp]
  if (!pdpUrl) {
    context.log.error("PDP is not in certified PDP list.")
  }
  const gatewayPdpUrl = `${pdpUrl}/access/v1/evaluation`

  try {
    context.log.info(`Sending request to ${gatewayPdp} at ${gatewayPdpUrl}`)
    context.log.debug(`AuthZEN request: ${authzenRequest}`)

    const apiKey = environment.AUTHZEN_PDP_API_KEYS && environment.AUTHZEN_PDP_API_KEYS[gatewayPdp]
    const headers = {
      "content-type": "application/json",
    }
    if (apiKey) {
      headers["Authorization"] = apiKey
    }

    const authzenResponse = await fetch(gatewayPdpUrl, { 
      headers,
      method: 'POST',
      body: authzenRequest
    })
    const response = await authzenResponse.json()
    context.log.debug(`AuthZEN response: ${JSON.stringify(response)}`)

    if (response && response.decision) {
      return request
    }
    context.log.error(
      `The user '${request.user.sub}' is not authorized to perform this action.`,
    )
    return HttpProblems.forbidden(request, context);
  } catch (e) {
    context.log.error(
      `AuthZEN authorization error. The user '${request.user.sub}' is not authorized to perform this action.`,
    )
    return HttpProblems.forbidden(request, context);
  }
}
