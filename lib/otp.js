// Based https://github.com/taharactrl/otpauth-migration-parser
// modified to allow protobuf definition to be included inline rather than via a .proto file
const protobuf = require("protobufjs");
const { base32 } = require("rfc4648");

const ALGORITHM = {
  0: "unspecified",
  1: "sha1",
  2: "sha256",
  3: "sha512",
  4: "md5",
};

const DIGIT_COUNT = {
  0: "unspecified",
  1: 6,
  2: 8,
};

const OTP_TYPE = {
  0: "unspecified",
  1: "hotp",
  2: "totp",
};

const parser = (sourceUrl) => {
  if (typeof sourceUrl !== "string") {
    throw new Error("source url must be a string");
  }

  if (sourceUrl.indexOf("otpauth-migration://offline") !== 0) {
    throw new Error(
      "source url must be begun with otpauth-migration://offline"
    );
  }

  const sourceData = new URL(sourceUrl).searchParams.get("data");

  if (!sourceData) {
    throw new Error("source url doesn't contain otpauth data");
  }

  const protobufRoot = protobuf.Root.fromJSON(
    {
      "nested": {
        "MigrationPayload": {
          "fields": {
            "otpParameters": {
              "rule": "repeated",
              "type": "OtpParameters",
              "id": 1
            },
            "version": {
              "type": "int32",
              "id": 2
            },
            "batchSize": {
              "type": "int32",
              "id": 3
            },
            "batchIndex": {
              "type": "int32",
              "id": 4
            },
            "batchId": {
              "type": "int32",
              "id": 5
            }
          },
          "nested": {
            "Algorithm": {
              "values": {
                "ALGORITHM_UNSPECIFIED": 0,
                "ALGORITHM_SHA1": 1,
                "ALGORITHM_SHA256": 2,
                "ALGORITHM_SHA512": 3,
                "ALGORITHM_MD5": 4
              }
            },
            "DigitCount": {
              "values": {
                "DIGIT_COUNT_UNSPECIFIED": 0,
                "DIGIT_COUNT_SIX": 1,
                "DIGIT_COUNT_EIGHT": 2
              }
            },
            "OtpType": {
              "values": {
                "OTP_TYPE_UNSPECIFIED": 0,
                "OTP_TYPE_HOTP": 1,
                "OTP_TYPE_TOTP": 2
              }
            },
            "OtpParameters": {
              "fields": {
                "secret": {
                  "type": "bytes",
                  "id": 1
                },
                "name": {
                  "type": "string",
                  "id": 2
                },
                "issuer": {
                  "type": "string",
                  "id": 3
                },
                "algorithm": {
                  "type": "Algorithm",
                  "id": 4
                },
                "digits": {
                  "type": "DigitCount",
                  "id": 5
                },
                "type": {
                  "type": "OtpType",
                  "id": 6
                },
                "counter": {
                  "type": "int64",
                  "id": 7
                }
              }
            }
          }
        }
      }
    }

  );

  const migrationPayload = protobufRoot.lookupType("MigrationPayload");
  const decodedOtpPayload = migrationPayload.decode(
    Buffer.from(sourceData, "base64")
  );

  const otpParameters = [];
  for (let otpParameter of decodedOtpPayload.otpParameters) {
    otpParameters.push({
      secret: base32.stringify(otpParameter.secret),
      name: otpParameter.name,
      issuer: otpParameter.issuer,
      algorithm: ALGORITHM[otpParameter.algorithm],
      digits: DIGIT_COUNT[otpParameter.digits],
      type: OTP_TYPE[otpParameter.type],
      counter: otpParameter.counter,
    });
  }

  return otpParameters;
};

module.exports = parser;
