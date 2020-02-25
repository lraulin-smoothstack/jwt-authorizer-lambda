"use strict";

const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const axios = require("axios");

const denyAllPolicy = () => ({
  principalId: "*",
  policyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "*",
        Effect: "Deny",
        Resource: "*",
      },
    ],
  },
});

const allowPolicy = methodArn => ({
  principalId: "apigateway.amazonaws.com",
  policyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "execute-api:Invoke",
        Effect: "Allow",
        Resource: methodArn,
      },
    ],
  },
});

// const getEncodedToken = header => {
//   try {
//     header.split(" ")[1];
//   } catch {
//     return null;
//   }
// };

// const getJwkByKid = async (iss, kid) => {
//   const jwksendpoint = iss + "/.well-known/jwks.json";
//   const json = await axios(jwksendpoint);

//   for (let index = 0; index < json.data.keys.length; index++) {
//     const key = json.data.keys[index];

//     if (key.kid === kid) return key;
//   }
// };

const getMethod = arn => arn.split("/")[2];

const getResource = arn =>
  "/" +
  arn
    .split("/")
    .slice(3)
    .join("/");

/**
 * Logic for resource access by role
 */
const allowOrDenyPolicy = event => {
  // const encodedToken = getEncodedToken(event.authorizationToken);
  const encodedToken = event.authorizationToken;
  const token = jwt.decode(encodedToken, { complete: true });
  // const jwk = await getJwkByKid(token.payload.iss, token.header.kid);
  // const pem = jwkToPem(jwk);
  // jwt.verify(encodedToken, pem);
  const role = token.payload.role;
  console.log("ROLE: " + role);
  const method = getMethod(event.methodArn);
  console.log("METHOD: " + method);
  const resource = getResource(event.methodArn);
  console.log("RESOURCE: " + resource);

  console.log(`User with role ${role} attempting a ${method} on ${resource}`);
  // GET /products
  if (
    method === "GET" &&
    resource === "/products" &&
    ["customer", "clerk", "admin"].includes(role)
  ) {
    return allowPolicy(event.methodArn);
  }

  // GET /products/{product_id}
  if (method === "GET" && resource === "/products/{product_id}") {
    return allowPolicy(event.methodArn);
  }

  // POST /products
  if (method === "POST" && resource === "/products") {
    console.log("POST /products");
    const authorizedRoles = ["clerk", "admin"];
    const authorized = authorizedRoles.includes(role);
    if (authorized) {
      console.log("AUTHORIZED");
      return allowPolicy(event.methodArn);
    } else {
      console.log("NOT AUTHORIZED");
      return denyAllPolicy();
    }
  }

  // Default case
  return denyAllPolicy();
};

/**
 * Entry point
 */
exports.handler = async event => {
  console.log(event);
  try {
    return allowOrDenyPolicy(event);
  } catch (error) {
    console.error(error.message);
    return denyAllPolicy();
  }
};
