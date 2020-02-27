"use strict";

const jwt = require("jsonwebtoken");

const ADMIN = 4;
const ACCOUNTANT = 3;
const CLERK = 2;
const CUSTOMER = 1;

// Test methodArn string for allowed method/resource combinations
const isEmail = userEmail =>
  /([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/.test(userEmail);

const isUserEndpoint = (userEmail, methodArn) =>
  new RegExp("/(GET|PUT|DELETE)/users/" + userEmail + "$").test(methodArn);

const isAccountantEndpoint = methodArn =>
  /\/orders\/(taxes|reports)$/.test(methodArn);

const isClerkEndpoint = methodArn =>
  /\/orders(\/\d+)?$/.test(methodArn) || methodArn.includes("/products");

const isCustomerEndpoint = methodArn => /POST\/orders$/.test(methodArn);

const userIsAuthorized = (userEmail, userRole, methodArn) => {
  console.log(
    `authorizeUser ${JSON.stringify(userEmail)} ${JSON.stringify(
      userRole,
    )} ${methodArn}`,
  );

  // Any user can do any action on their /users/:email resource
  if (isEmail(userEmail) && isUserEndpoint(userEmail, methodArn)) {
    return true;
  }

  // Authorization by role
  switch (userRole) {
    case ADMIN:
      return true;
    case ACCOUNTANT:
      if (isAccountantEndpoint) return true;
      break;
    case CLERK:
      if (isClerkEndpoint) return true;
      break;
    case CUSTOMER:
      if (isCustomerEndpoint) return true;
      break;
    default:
      return false;
  }
};

const buildIAMPolicy = (userId, effect, resource, context) => {
  console.log(`buildIAMPolicy ${userId} ${effect} ${resource}`);
  const policy = {
    principalId: userId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
    context,
  };

  console.log(JSON.stringify(policy));
  return policy;
};

const tokenRxResult = t =>
  /[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/.exec(t);

const getToken = authorizationToken =>
  tokenRxResult(authorizationToken) && tokenRxResult(authorizationToken)[0];

const handler = (event, context, callback) => {
  console.log("authorize");
  console.log(event);

  const token = getToken(event.authorizationToken);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(JSON.stringify(decoded));

    // Checks if the user's scopes allow her to call the current endpoint ARN
    const email = decoded.email;
    const role = decoded.role;
    const isAllowed = userIsAuthorized(email, role, event.methodArn);

    // Return an IAM policy document for the current endpoint
    const effect = isAllowed ? "Allow" : "Deny";
    const authorizerContext = { email: JSON.stringify(email) };
    const policyDocument = buildIAMPolicy(
      email,
      effect,
      event.methodArn,
      authorizerContext,
    );

    console.log("Returning IAM policy document");
    callback(null, policyDocument);
  } catch (e) {
    console.log(e.message);
    callback("Unauthorized"); // Return a 401 Unauthorized response
  }
};

module.exports = {
  handler,
  isEmail,
  isUserEndpoint,
  isAccountantEndpoint,
  isClerkEndpoint,
  isCustomerEndpoint,
  userIsAuthorized,
  buildIAMPolicy,
  tokenRxResult,
  getToken,
};
