const { expect } = require("chai");
const XJWT = require("../src/xjwt");
const AES_KEY = "SbYymvfZ8UjEmShxRAB0b1Dtaa0uGjDOOJa/f0Mbuo4=";
const SECRET_KEY = "16jmp2";
const xjwt = new XJWT(AES_KEY, SECRET_KEY);

const token = decodeURIComponent(
  "AAABbP9f7FEBAAAAAAABiDA%3D.lImq8qLoe41dXF9SxNrQ1BkJO1wSSDVwchUqg%2FFNnp%2FVQh3FOv8lWzBR3GnhaR%2FnGFCjzW41Lp9daB3O653Qfj7iszfhdqKmjJMNayqEGAEYwrmIjOpYZTIraU5OB4GVcU%2FxZM5Wi2PGOZlninQEY%2Fh27Om9y709ARXzhugj4wtnHtErEASPG7o1S7lbKbBNyksxePlFFVD%2Bfds7AyxSjcpbcUDzih4R90XZ55BJuuxkc400%2Fgb0F0shVkl%2BsJKJIyCzAEVax2925YjSDS4jnnkXmL9fIEfqlnqKnDRjMbIyJYiaBinrG7El6Bj9C7aPDwRN%2B4%2FkCiAp8jkXtViw2g%3D%3D.cdAOiP7L6D3jDPHKHm%2BVYm62%2Flt2UPYqh%2BFofohht5I%3D"
);

describe("xjwt module test case", () => {
  let _token;
  const type = 1;
  const IssuerId = 100400;
  const Payload = {
    id: 10,
    un: "test",
    dis: "test_123456"
  };
  before(() => {
    xjwt.setToken(token);
  });

  it("test the xjwt decode function", () => {
    const { header, payload } = xjwt.decode();
    // expect header
    expect(header).ownProperty("expiry");
    expect(header.expiry).be.a("number");
    expect(header).ownProperty("type");
    expect(header.type).be.a("number");
    expect(header).ownProperty("issuerId");
    expect(header.issuerId).be.a("number");
    // expect payload
    expect(payload).be.a("string");
    let _payload = JSON.parse(payload);
    expect(_payload).be.a("object");
    expect(_payload).ownProperty("id");
    expect(_payload).ownProperty("un");
    expect(_payload).ownProperty("dis");
    expect(_payload.id).be.a("number");
    expect(_payload.un).be.a("string");
    expect(_payload.dis).be.a("string");
  });

  it("test the xjwt sign function", () => {
    _token = xjwt.sign(type, `${JSON.stringify(Payload)}`, IssuerId);
    expect(_token).be.a("string");
  });

  it("test the xjwt decode self sign", () => {
    xjwt.setToken(_token);
    let decode = xjwt.decode();
    expect(decode).be.a("object");
    expect(decode.header).be.a("object");
    expect(decode.header.issuerId).equal(IssuerId);
    expect(decode.header.type).equal(1);
    expect(decode.payload).be.a("string");
    console.log(decode.payload);
    let _payload = JSON.parse(decode.payload);
    expect(_payload).to.deep.equal(Payload);
  });
});
