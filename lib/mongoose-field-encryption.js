"use strict";

const crypto = require("crypto");
const mpath = require("mpath");

const algorithm = "aes-256-cbc";
const deprecatedAlgorithm = "aes-256-ctr";
const encryptedFieldNamePrefix = "__enc_";
const encryptedFieldDataSuffix = "_d";

const encryptAes256Ctr = function (text, secret) {
  const cipher = crypto.createCipher(deprecatedAlgorithm, secret);
  let crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};

const decryptAes256Ctr = function (encryptedHex, secret) {
  const decipher = crypto.createDecipher(deprecatedAlgorithm, secret);
  let dec = decipher.update(encryptedHex, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
};

const encrypt = function (clearText, secret, saltGenerator) {
  const iv = saltGeneratorWrapper(saltGenerator(secret));
  const cipher = crypto.createCipheriv(algorithm, secret, iv);
  const encrypted = cipher.update(clearText);
  const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
  const encryptedHex = iv.toString("hex") + ":" + finalBuffer.toString("hex");
  return encryptedHex;
};

const saltGeneratorWrapper = (iv) => {
  if (iv instanceof Buffer) {
    if (iv.length !== 16) {
      throw new Error("Invalid salt provided, please ensure that the salt is a Buffer of length 16");
    }
    return iv;
  }

  if (typeof iv === "string" || iv instanceof String) {
    if (iv.length !== 16) {
      throw new Error("Invalid salt, please ensure that the salt is a string of length 16");
    }
    return Buffer.from(iv);
  }

  throw new Error("Invalid salt, please ensure that the salt is either a string or a Buffer of length 16");
};

const defaultSaltGenerator = (secret) => crypto.randomBytes(16);

/**
 * Decryption has a default fallback for the deprecated algorithm
 *
 * @param {*} encryptedHex
 * @param {*} secret
 */
const decrypt = function (encryptedHex, secret) {
  const encryptedArray = encryptedHex.split(":");

  // maintain backwards compatibility
  if (encryptedArray.length === 1) {
    return decryptAes256Ctr(encryptedArray[0], secret);
  }

  const iv = Buffer.from(encryptedArray[0], "hex");
  const encrypted = Buffer.from(encryptedArray[1], "hex");
  const decipher = crypto.createDecipheriv(algorithm, secret, iv);
  const decrypted = decipher.update(encrypted);
  const clearText = Buffer.concat([decrypted, decipher.final()]).toString();
  return clearText;
};

const fieldEncryption = function (schema, options) {
  if (!options || !options.secret) {
    throw new Error("missing required secret");
  }

  const useAes256Ctr = options.useAes256Ctr || false;
  const fieldsToEncrypt = options.fields || [];
  const nestedSchemaToEncrypt = [];

  const _secret = typeof options.secret === "function" ? options.secret : () => options.secret;

  const _hash = (secret) => crypto.createHash("sha256").update(secret).digest("hex").substring(0, 32);

  const secret = useAes256Ctr ? _secret : () => _hash(_secret());
  const encryptionStrategy = useAes256Ctr ? encryptAes256Ctr : encrypt;
  const saltGenerator = options.saltGenerator ? options.saltGenerator : defaultSaltGenerator;

  // add marker fields to schema
  for (const field of fieldsToEncrypt) {
    const encryptedFieldName = encryptedFieldNamePrefix + field;
    const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
    const schemaField = {};

    schemaField[encryptedFieldName] = { type: Boolean };
    schemaField[encryptedFieldData] = { type: String };
    schema.add(schemaField);
  }

  loopNestedSchema(schema);

  //
  // local methods
  //

  // for mongoose 4/5 compatibility
  const defaultNext = function defaultNext(err) {
    if (err) {
      throw err;
    }
  };

  function getCompatitibleNextFunc(next) {
    if (typeof next !== "function") {
      return defaultNext;
    }
    return next;
  }

  function getCompatibleData(next, data) {
    // in mongoose5, 'data' field is undefined
    if (!data) {
      return next;
    }
    return data;
  }

  function encryptFields(obj, fields, secret) {
    for (const field of fields) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
      const fieldValue = obj[field];

      if (!obj[encryptedFieldName] && typeof fieldValue !== "undefined") {
        if (typeof fieldValue === "string") {
          // handle strings separately to maintain searchability
          const value = encryptionStrategy(fieldValue, secret, saltGenerator);
          obj[field] = value;
        } else {
          const value = encryptionStrategy(JSON.stringify(fieldValue), secret, saltGenerator);
          obj[field] = undefined;
          obj[encryptedFieldData] = value;
        }

        obj[encryptedFieldName] = true;
      }
    }

    for (const part of nestedSchemaToEncrypt) {
      const path = part.path;
      const schema = part.schema;
      const value = mpath.get(path, obj);

      let result = null;

      if (value) {
        if (Array.isArray(value)) {
          result = loopEncrypt(schema, value);
        } else {
          result = value;
          schema.methods.encryptFieldsSync.call(result);
        }
      }

      if (result) {
        mpath.set(path, result, obj);
      }
    }
  }

  function decryptFields(obj, fields, secret) {
    for (const field of fields) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

      if (obj[encryptedFieldName]) {
        if (obj[encryptedFieldData]) {
          const encryptedValue = obj[encryptedFieldData];

          obj[field] = JSON.parse(decrypt(encryptedValue, secret));
          obj[encryptedFieldName] = false;
          obj[encryptedFieldData] = "";
        } else {
          // If the field has been marked to not be retrieved, it'll be undefined
          if (obj[field]) {
            // handle strings separately to maintain searchability
            const encryptedValue = obj[field];
            obj[field] = decrypt(encryptedValue, secret);
            obj[encryptedFieldName] = false;
          }
        }
      }
    }

    for (const part of nestedSchemaToEncrypt) {
      const path = part.path;
      const schema = part.schema;
      const value = mpath.get(path, obj);

      let result = null;

      if (value) {
        if (Array.isArray(value)) {
          result = loopDecrypt(schema, value);
        } else {
          result = value;
          schema.methods.decryptFieldsSync.call(result);
        }
      }

      if (result) {
        mpath.set(path, result, obj);
      }
    }
  }

  function updateHook(_next) {
    const next = getCompatitibleNextFunc(_next);
    const updateObj = {};

    for (const field of fieldsToEncrypt) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      this._update.$set = this._update.$set || {};
      const plainTextValue = this._update.$set[field] || this._update[field];
      const encryptedFieldValue = this._update.$set[encryptedFieldName] || this._update[encryptedFieldName];

      if (!encryptedFieldValue && plainTextValue) {
        if (typeof plainTextValue === "string" || plainTextValue instanceof String) {
          const encryptedData = encryptionStrategy(plainTextValue, secret(), saltGenerator);

          updateObj[field] = encryptedData;
          updateObj[encryptedFieldName] = true;
        } else {
          const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

          updateObj[field] = undefined;
          updateObj[encryptedFieldData] = encryptionStrategy(JSON.stringify(plainTextValue), secret(), saltGenerator);
          updateObj[encryptedFieldName] = true;
        }
      }
    }

    this.update({}, updateObj);
    next();
  }

  function loopNestedSchema(_schema, _path) {
    const _obj = _schema.obj;
    const _keys = Object.keys(_obj);

    for (const _key of _keys) {
      const _value = getSchema(_obj[_key]);

      if (!_value) {
        continue;
      }

      const _chain = _path ? _path + "." + _key : _key;

      if (findSchemaHasEncryptFields(_value)) {
        nestedSchemaToEncrypt.push({
          path: _chain,
          schema: _value,
        });
      }

      loopNestedSchema(_value, _chain);
    }
  }

  function getSchema(_value) {
    let _schema = null;

    if (Array.isArray(_value)) {
      _schema = _value[0];
    } else {
      _schema = _value;
    }

    if (!_schema || !_schema.methods) {
      return null;
    }

    const encryptFunc = _schema.methods.encryptFieldsSync;
    const decryptFunc = _schema.methods.decryptFieldsSync;

    if (encryptFunc && decryptFunc && typeof encryptFunc === "function" && typeof decryptFunc === "function") {
      return _schema;
    }

    return null;
  }

  function findSchemaHasEncryptFields(_schema) {
    const _tree = _schema.tree;
    const _keys = Object.keys(_tree);
    return _keys.some((key) => key.startsWith(encryptedFieldNamePrefix));
  }

  function loopEncrypt(schema, array) {
    for (let i = 0; i < array.length; i++) {
      if (!array[i]) {
        continue;
      }

      if (Array.isArray(array[i])) {
        loopEncrypt(schema, array[i]);
      } else {
        schema.methods.encryptFieldsSync.call(array[i]);
      }
    }

    return array;
  }

  function loopDecrypt(schema, array) {
    for (let i = 0; i < array.length; i++) {
      if (!array[i]) {
        continue;
      }

      if (Array.isArray(array[i])) {
        loopDecrypt(schema, array[i]);
      } else {
        schema.methods.decryptFieldsSync.call(array[i]);
      }
    }

    return array;
  }

  //
  // static methods
  //

  schema.methods.stripEncryptionFieldMarkers = function () {
    for (const field of fieldsToEncrypt) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

      this.set(encryptedFieldName, undefined);
      this.set(encryptedFieldData, undefined);
    }
  };

  schema.methods.decryptFieldsSync = function () {
    decryptFields(this, fieldsToEncrypt, secret());
  };

  schema.methods.encryptFieldsSync = function () {
    encryptFields(this, fieldsToEncrypt, secret());
  };

  //
  // hooks
  //

  schema.post("init", function (_next, _data) {
    const next = getCompatitibleNextFunc(_next);
    const data = getCompatibleData(_next, _data);
    try {
      decryptFields(data, fieldsToEncrypt, secret());
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre("save", function (_next) {
    const next = getCompatitibleNextFunc(_next);

    try {
      encryptFields(this, fieldsToEncrypt, secret());
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre("insertMany", function (_next, _docs) {
    const next = getCompatitibleNextFunc(_next);
    const docs = getCompatibleData(_next, _docs);

    try {
      for (const doc of docs) {
        encryptFields(doc, fieldsToEncrypt, secret());
      }
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre("findOneAndUpdate", updateHook);
  schema.pre("update", updateHook);
  schema.pre("updateOne", updateHook);
  schema.pre("updateMany", updateHook);
};

module.exports.fieldEncryption = fieldEncryption;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
module.exports.encryptAes256Ctr = encryptAes256Ctr;
