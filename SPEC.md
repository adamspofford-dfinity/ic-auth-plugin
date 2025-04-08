# Specification

An IC auth plugin is a program which is invoked with `--ic-auth-plugin` as its first argument. It receives and sends one-line JSON messages followed by a newline over stdin and stdout respectively. Its signal to gracefully shut down is its stdin being closed. After a plugin greets the host, it sends no data proactively, only responding when the host sends a request.

Plugins should respond to all well-formed requests with well-formed responses; even if a plugin does not support a particular operation, it should say so with an error response rather than aborting. It is however correct to abort if the plugin requires key selection and the host does not perform it (see below).

A single instance of a plugin process should only represent one signing key, even if a plugin represents a mechanism that contains more than one key. A plugin may require input (see below) to select which key to use. Plugins must support multiple concurrent process instances to enable a host to select multiple keys.

The following message structures are displayed in this document with newlines, but must be sent without newlines. All fields are required unless specified otherwise.

## Basic response structure

A response to a request can be successful, or an error.

All successful responses take the following structure:

```json
{
    "Ok": {
        // response content
    }
}
```

All error responses take the following structure:

```json
{
    "Err": {
        "kind": "some-error-case"
        // other error content
    }
}
```

Requests have defined error cases, specified in the `kind` field, but all requests support the `custom` error case:

```json
{
    "Err": {
        "kind": "custom",
        "message": "Oh no!"
    }
}
```

Plugins should use the `custom` case for plugin-specific error cases not defined by the specification, and must provide a human-readable message in `message`.

## Greeting

A greeting must be sent by the plugin immediately after being invoked. A host must send no requests until the plugin has sent a greeting.

```json
{
    "v": [1],
    "select": "required" // optional
}
```

A greeting indicates the versions of the ic-auth-plugin interface that the plugin supports. All message structures have a `v` field to indicate what version they are for. Nonstandard protocol extensions should be marked with string versions starting with `#`; integers and strings not starting with `#` are reserved. Hosts must not send plugins any messages with versions they do not support.

A plugin may optionally indicate that it supports key selection. The `select` field can be set to `required`, `supported`, or `unsupported`, and if absent is assumed to be `unsupported`.

## Key selection

A key selection request may be sent by the host to instruct the plugin which of its keys should be used for the remainder of the session. The host must send no messages other than "list selectable keys" before selecting a key, and must not select a key more than once. The host should not send this request to plugins that did not declare selection support in their greeting, and the host must not send requests without selecting a key to a plugin that declared selection to be required.

A key is selected by a name string. This name should not be secret; any required authentication should be performed separately by the plugin. The name should be enterable by a user. A key may have multiple names.

```json
{
    "v": 1,
    "action": "select-key",
    "key": "<name of the key>"
}
```

### Response

```json
{"Ok":{}}
```

### Errors

```json
{"Err":{
    "kind": "unsupported"
}}
```

Indicates that the plugin does not support key selection.

```json
{"Err":{
    "kind": "invalid-key",
    "message": "Keys must be alphanumeric" // optional
}}
```

Indicates that the key name was not valid for the plugin. `message` is optional, and should be human-readable.

## List selectable keys

A host may request the list of keys it can select, so as to render it in a drop-down or similar. A plugin does not need to have a known list of keys, but if it does, it should respond with the list.

```json
{
    "v": 1,
    "action": "list-selectable-keys"
}
```

### Response

```json
{"Ok":{
    "keys": ["<name of the first key>", "<name of the second key>", /* etc */],
    "exhaustive": false
}}
```

The `exhaustive` field, if set to false, indicates that a host that renders the keys in a dropdown or similar should also allow the user to enter an arbitrary string, as it would if listing keys is unsupported by the plugin.

### Errors

```json
{"Err":{
    "kind": "unsupported"
}}
```

Indicates that the plugin's keys cannot be listed.

## Request for a public key

A public key request is sent to learn the public key corresponding to the private key which the plugin will use for the current session. All plugins must support this operation.

```json
{
    "v": 1,
    "action": "get-public-key"
}
```

### Response

```json
{"Ok":{
    "public-key-der": "<base64-encoded DER representation>"
}}
```

Public key encoding is defined by the IC specification, and unversioned; hosts should be prepared to deal with keys in encodings they do not know about, but v1 plugins must only send keys that can be blindly converted to self-authenticating principals.

## Request for a delegation

A host may ask a plugin to sign a delegation, allowing the host to do its own signing on behalf of the plugin. Plugins do not have to support this request.

```json
{
    "v": 1,
    "action": "sign-delegation",
    "public-key-der": "<base64-encoded DER representation>",
    "desired-expiry": 1743729765,
    "desired-canisters": ["ryjl3-tyaaa-aaaaa-aaaba-cai", /* etc */] // optional
}
```

Public key encoding is defined by the IC specification, and unversioned; plugins should be prepared to sign keys with encodings they do not know about, but v1 hosts must only send keys that can be delegated to without additional context besides the current time. `desired-canisters` is optional, but some plugins may require it nonetheless.

### Response

```json
{"Ok":{
    "signature": "<base64-encoded DER representation>",
    "expiry": 1743729765
}}
```

The resulting delegation must be a wildcard delegation if `desired-canisters` was omitted, and must be scoped to the exact list of canisters in `desired-canisters` if it was specified. In other words, the host must be able to predict the signed hash after it learns the delegation expiry. A desired expiry further in the future than the plugin supports is not an error; in such a case the plugin should sign the furthest-future delegation it supports, and describe the expiry it actually used in the `expiry` field. The `expiry` field is required whether or not the plugin has done this.

### Errors

```json
{"Err":{
    "kind": "unsupported"
}}
```

Indicates that the plugin does not support delegations.

```json
{"Err":{
    "kind": "needs-canister-scoping"
}}
```

Indicates that the plugin does not support wildcard delegations, and requires the `desired-canisters` field to be filled.

```json
{"Err":{
    "kind": "unsupported-canister",
    "principals": ["ryjl3-tyaaa-aaaaa-aaaba-cai"],
    "message": "Not that one!" // optional
}}
```

Indicates that the plugin does not support delegations to one of the canisters in `desired-canisters`. The plugin should include every desired principal it rejected, but may list other unsupported principals as well for completeness. `message` is optional, and should be human-readable.

```json
{"Err":{
    "kind": "refused"
}}
```

Indicates that the user was asked about this request, and they refused. This error should not be used for automated responses.

## Request for a message envelope signature

A host may ask a plugin to sign an envelope for an ingress message. All plugins must support this operation.

```json
{
    "v": 1,
    "action": "sign-envelopes",
    "contents": [{ /* content map */ }, /* etc */]
}
```

The `contents` field can contain multiple messages to sign. The primary purpose of this is to enable user confirmation of both an `update` message and a `read_state` message for its request ID at the same time. If the host intends this, it should order the list so that the `update` message is immediately followed by its corresponding `read_state` message. Each element of the list is the `content` map from the authentication envelope.

### Response

```json
{"Ok":{
    "signatures": ["<base64-encoded DER representation>", /* etc */]
}}
```

The signatures must be in the same order as the envelopes.

### Errors

```json
{"Err":{
    "kind": "refused"
}}
```

Indicates that the user was asked about this request, and they refused. This error should not be used for automated responses.

```json
{"Err":{
    "kind": "unsupported-content",
    "pos": [0],
    "message": "Candid only!" // optional
}}
```

Indicates that the plugin does not support one or more messages it was asked to sign for any reason (argument encoding, canister target, etc). `pos` should contain the positions in the envelope list of all unsupported messages. `message` is optional, and should be human-readable.

## Request for an arbitrary signature

A host may ask a plugin to sign arbitrary data. Plugins do not have to support this operation. This request should not be used for nonstandard protocol extensions; those should define their own `v` and `action`.

```json
{
    "v": 1,
    "action": "sign-arbitrary-data",
    "data": "<base64-encoded bytes>"
}
```

### Response

```json
{"Ok":{
    "signature": "<base64-encoded DER representation>"
}}
```

### Errors

```json
{"Err":{
    "kind": "unsupported"
}}
```

Indicates that signing arbitrary data is unsupported by the plugin.

