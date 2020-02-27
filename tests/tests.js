const expect = require("chai").expect;
const {
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
} = require("../index");

describe("MethodARN matchers", function(done) {
  describe("isEmail", function(done) {
    it("returns true when string is email", function(done) {
      const email = "test@example.org";
      const result = isEmail(email);
      expect(result).to.be.true;
      done();
    });

    it("returns false when string is not email", function(done) {
      const email = "test4example_org";
      const result = isEmail(email);
      expect(result).to.be.false;
      done();
    });
  });

  describe("isUserEndpoint", function(done) {
    it("returns true when endpoint is user's own /[METHOD]/users/:email", function(done) {
      const email = "test@example.org";
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/DELETE/users/" +
        email;
      const result = isUserEndpoint(email, arn);
      expect(result).to.be.true;
      done();
    });

    it("returns false when arn is invalid", function(done) {
      const email = "test@example.org";
      const arn =
        "arn:aws:/DELETE/users/" +
        email +
        "execute-api:us-west-2:123456789012:ymy8tbxw7b/*";
      email;
      const result = isUserEndpoint(email, arn);
      expect(result).to.be.false;
      done();
    });

    it("returns false when email is not user's own", function(done) {
      const email = "test@example.org";
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/DELETE/users/something@else.com";
      const result = isUserEndpoint(email, arn);
      expect(result).to.be.false;
      done();
    });
  });

  describe("isAccountantEndpoint", function(done) {
    it("is true when resource is /orders/taxes", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/orders/taxes";
      const result = isAccountantEndpoint(arn);
      expect(result).to.be.true;
      done();
    });

    it("is true when resource is /orders/reports", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/PUT/orders/taxes";
      const result = isAccountantEndpoint(arn);
      expect(result).to.be.true;
      done();
    });

    it("is false when resource is orders but not reports or taxes", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/orders";
      const result = isAccountantEndpoint(arn);
      expect(result).to.be.false;
      done();
    });

    it("is false when endpoint path is in wrong position", function(done) {
      const arn =
        "arn:aws:execute-api:u/GET/orders/taxess-west-2:123456789012:ymy8tbxw7b/*";
      const result = isAccountantEndpoint(arn);
      expect(result).to.be.false;
      done();
    });
  });

  describe("isClerkEndpoint", function(done) {
    it("is true when endpoint is /orders", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/PUT/orders";
      const result = isClerkEndpoint(arn);
      expect(result).to.be.true;
      done();
    });

    it("is true when endpoint is /orders/:id", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/PUT/orders/8675309";
      const result = isClerkEndpoint(arn);
      expect(result).to.be.true;
      done();
    });

    it("is false when endpoint is /orders/taxes", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/PUT/orders/taxes";
      const result = isClerkEndpoint(arn);
      expect(result).to.be.false;
      done();
    });
  });

  describe("isCustomerEndpoint", function(done) {
    it("is true when endpoint is POST/orders", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/POST/orders";
      const result = isCustomerEndpoint(arn);
      expect(result).to.be.true;
      done();
    });

    it("is false when endpoint is GET/orders", function(done) {
      const arn =
        "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/orders";
      const result = isCustomerEndpoint(arn);
      expect(result).to.be.false;
      done();
    });
  });

  describe("JSON web token extraction", function(done) {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    it("returns token when preceded by 'Bearer '", function(done) {
      const header = "Bearer " + token;
      const result = getToken(tokenRxResult(header));
      expect(result).to.equal(token);
      done();
    });

    it("returns token when preceded by nothing", function(done) {
      const header = token;
      const result = getToken(tokenRxResult(header));
      expect(result).to.equal(token);
      done();
    });

    it("returns token header does not contain possible token", function(done) {
      const header = "Bearer snthXEOHTXU24682>064202nhdnbNBMWb";
      const result = getToken(tokenRxResult(header));
      expect(result).to.be.a("null");
      done();
    });
  });
});
