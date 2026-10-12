//! The OpenAPI document: derived from the route table, served from the
//! committed file.
//!
//! Automated callers discover the platform through this document, so it is a
//! product surface rather than generated reference material. Its job is to let a
//! caller authenticate, publish, and recover from every error without a human
//! reading a guide.
//!
//! # One description of each route
//!
//! Every operation is built from an entry in [`production_routes`]. The verb,
//! path, scope and handler are the table's, and the documentation lives in the
//! same entry as a [`Doc`]. There are no `#[utoipa::path]` annotations: an
//! annotation carries its own path and method, which would be a second
//! description of the route with nothing tying it back to the first. Body schemas
//! come from `#[derive(ToSchema)]` on the types the handlers serialise, and every
//! example is one of those types, serialised.
//!
//! What the table cannot guarantee, a test checks. The envelope probe records
//! the codes each production route actually produces and fails if the document
//! does not list them for that route. It cannot catch the reverse, a documented
//! code that is never produced: `internal` and `timeout` cannot be provoked on a
//! real route.
//!
//! # Served bytes are the checked bytes
//!
//! [`COMMITTED`] is `openapi.json` from this crate, embedded at compile time and
//! served as it is. The tests assert that regenerating it produces the same bytes
//! (`just openapi` regenerates it), validate it against the OpenAPI 3.1 JSON
//! Schema, and check every example against its schema. So what a caller fetches,
//! what CI checks and what a reviewer reads in a diff are one file.
//!
//! `openapi-3.1-schema.json` beside it is the OpenAPI Initiative's published
//! JSON Schema for OpenAPI 3.1 (version 2022-10-07, Apache-2.0), vendored so
//! validation needs no network.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use shared::error::{CATALOGUE, DELEGATED_HINT, DELEGATED_MEANING, bundle_sample, owned_samples};
use shared::{Envelope, RequestId};
use utoipa::ToSchema;
use utoipa::openapi::content::{Content, ContentBuilder};
use utoipa::openapi::example::ExampleBuilder;
use utoipa::openapi::header::HeaderBuilder;
use utoipa::openapi::path::{HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn};
use utoipa::openapi::request_body::RequestBodyBuilder;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::schema::{
    AdditionalProperties, KnownFormat, ObjectBuilder, SchemaFormat, SchemaType, Type,
};
use utoipa::openapi::security::{
    ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme,
};
use utoipa::openapi::{
    ComponentsBuilder, InfoBuilder, OpenApi, OpenApiBuilder, Paths, Ref, RefOr, Required, Schema,
};

use crate::http::{Access, Route, Verb, production_routes};

/// The document as committed and served, byte for byte.
pub const COMMITTED: &str = include_str!("../openapi.json");

const SECURITY_SCHEME: &str = "bearerAuth";
const COOKIE_SCHEME: &str = "sessionCookie";
const SESSION_AUTHENTICATION: &str = "**Authentication:** a browser session cookie, set by Google sign-in (`GET /auth/google`). A state-changing request must also come from the control plane's own origin: `Sec-Fetch-Site: same-origin`, or, without that header, an exact `Origin` match. Other pages on the same site, including every app under the apex, are refused.";
const ENVELOPE: &str = "Envelope";
const JSON: &str = "application/json";

/// How the delegated `bundle.*` family is named in a route's error list.
pub(crate) const BUNDLE_CODES: &str = "bundle.*";

const BUNDLE_TABLE: &str = "https://github.com/clwdrun/clwd/blob/main/docs/error-codes.md";

/// Fixed identifiers for examples, so the committed document is stable. Each is
/// a real UUIDv7 shape, never a real resource.
pub(crate) const EXAMPLE_ORG: uuid::Uuid =
    uuid::Uuid::from_u128(0x0198f0c1_8b3e_7000_8000_0000000000a1);
pub(crate) const EXAMPLE_APP: uuid::Uuid =
    uuid::Uuid::from_u128(0x0198f0c1_8b3e_7000_8000_0000000000a2);
pub(crate) const EXAMPLE_VERSION: uuid::Uuid =
    uuid::Uuid::from_u128(0x0198f0c1_8b3e_7000_8000_0000000000a3);
pub(crate) const EXAMPLE_TOKEN: uuid::Uuid =
    uuid::Uuid::from_u128(0x0198f0c1_8b3e_7000_8000_0000000000a4);
pub(crate) const EXAMPLE_CLAIM: uuid::Uuid =
    uuid::Uuid::from_u128(0x0198f0c1_8b3e_7000_8000_0000000000a6);
const EXAMPLE_REQUEST_ID: &str = "0198f0c1-8b3e-7000-8000-0000000000a5";

const AUTHENTICATION: &str = "A token looks like `clwd_tok_` followed by 64 lowercase hex characters, and is sent as `Authorization: Bearer <token>`. \
Each operation names the one scope its token must carry; scopes are independent, so `admin` does not imply `publish`.\n\n\
Tokens are issued by `POST /v1/orgs/{org_id}/tokens`, which itself needs an `admin` token. Until sign-in exists, an org's first token is created by an operator with database access (`control-plane bootstrap-token`): there is no way to obtain a first token through this API.";

/// Why the document could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpecError {
    /// A production route has no documentation.
    #[error("{0}: a production route with no documentation")]
    Undocumented(&'static str),
    /// A route lists an error code no catalogue declares.
    #[error("{route}: documents error code {code}, which no catalogue declares")]
    UnknownCode {
        route: &'static str,
        code: &'static str,
    },
    /// A path parameter has no description.
    #[error("{route}: path parameter {{{name}}} has no description")]
    UndescribedParameter { route: &'static str, name: String },
    /// A description names a parameter the path does not have.
    #[error("{route}: describes parameter {name}, which the path does not have")]
    StrayParameter {
        route: &'static str,
        name: &'static str,
    },
    /// An owned code has no sample to show as its example.
    #[error("owned code {0} has no sample error to show as its example")]
    NoSample(&'static str),
    /// The fixed example request id would be rejected by the API.
    #[error("the example request id is not one the API would accept")]
    ExampleRequestId,
    /// Serialising the document or an example failed.
    #[error("serialising the document or an example: {0}")]
    Json(#[from] serde_json::Error),
}

/// An example, produced by serialising a real value of the documented type.
pub(crate) type ExampleFn = fn() -> serde_json::Result<Value>;

/// Where a body's schema comes from.
pub(crate) enum SchemaSource {
    /// A type's derived schema, registered as a component together with every
    /// schema it refers to.
    Component(fn() -> NamedSchemas),
    /// A schema with no Rust type behind it: plain text, raw bytes.
    Inline(fn() -> Schema),
}

/// A request or response body.
pub(crate) struct Body {
    content_type: &'static str,
    description: &'static str,
    schema: SchemaSource,
    example: Option<ExampleFn>,
}

impl Body {
    /// A JSON body whose schema is `T`'s, with an example built from a `T`.
    pub(crate) fn json<T: ToSchema>(description: &'static str, example: ExampleFn) -> Self {
        Self {
            content_type: JSON,
            description,
            schema: SchemaSource::Component(component::<T>),
            example: Some(example),
        }
    }

    /// Raw bytes. No example: a blob in a document teaches a caller nothing,
    /// so the description says where the bytes come from instead.
    pub(crate) fn binary(content_type: &'static str, description: &'static str) -> Self {
        Self {
            content_type,
            description,
            schema: SchemaSource::Inline(binary_schema),
            example: None,
        }
    }

    /// This document itself.
    pub(crate) fn openapi_document(description: &'static str) -> Self {
        Self {
            content_type: JSON,
            description,
            schema: SchemaSource::Inline(object_schema),
            example: None,
        }
    }
}

/// One success response.
pub(crate) struct Success {
    pub(crate) status: StatusCode,
    pub(crate) description: &'static str,
    pub(crate) body: Option<Body>,
}

/// How a route is documented. It lives in the route's table entry, so an
/// operation cannot be documented without a route to serve it.
pub(crate) struct Doc {
    pub(crate) operation_id: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) description: &'static str,
    /// A description for each path parameter, by name.
    pub(crate) params: &'static [(&'static str, &'static str)],
    pub(crate) request: Option<Body>,
    pub(crate) success: Vec<Success>,
    /// Error codes particular to this route. Those every route or every
    /// protected route can produce are derived, not listed.
    pub(crate) errors: &'static [&'static str],
}

/// A type's schema under its name, and the named schemas it refers to.
type NamedSchemas = (String, RefOr<Schema>, Vec<(String, RefOr<Schema>)>);

fn component<T: ToSchema>() -> NamedSchemas {
    let mut referenced = Vec::new();
    T::schemas(&mut referenced);
    (T::name().into_owned(), T::schema(), referenced)
}

fn string_schema() -> Schema {
    ObjectBuilder::new().schema_type(Type::String).into()
}

fn binary_schema() -> Schema {
    ObjectBuilder::new()
        .schema_type(Type::String)
        .content_media_type("application/octet-stream")
        .into()
}

fn object_schema() -> Schema {
    ObjectBuilder::new().schema_type(Type::Object).into()
}

fn uuid_schema() -> Schema {
    ObjectBuilder::new()
        .schema_type(Type::String)
        .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid)))
        .into()
}

/// The error envelope. Written by hand because `shared` does not depend on
/// utoipa; every example in the document is a real serialised envelope, and
/// the tests validate each against this schema, so a field added or removed on
/// either side fails.
fn envelope_schema() -> Schema {
    let text = |description: &'static str| {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .description(Some(description))
    };
    ObjectBuilder::new()
        .description(Some(
            "Every 4xx and 5xx response carries this body. Branch on `code`; `message` is for people.",
        ))
        .property("code", text("A stable `<component>.<condition>` identifier."))
        .property("message", text("A human-readable account of this occurrence."))
        .property(
            "hint",
            ObjectBuilder::new()
                .schema_type(SchemaType::from_iter([Type::String, Type::Null]))
                .description(Some("What to do about it.")),
        )
        .property(
            "retryable",
            ObjectBuilder::new()
                .schema_type(Type::Boolean)
                .description(Some("Whether the same request, unchanged, could succeed later.")),
        )
        .property(
            "request_id",
            text("Correlates this response with server logs. Also sent as `x-request-id`."),
        )
        .required("code")
        .required("message")
        .required("hint")
        .required("retryable")
        .required("request_id")
        .additional_properties(Some(AdditionalProperties::FreeForm(false)))
        .into()
}

/// The names of a path's `{parameters}`, in order.
fn path_params(path: &str) -> Vec<&str> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

fn http_method(verb: Verb) -> HttpMethod {
    match verb {
        Verb::Get => HttpMethod::Get,
        Verb::Post => HttpMethod::Post,
        Verb::Put => HttpMethod::Put,
        Verb::Patch => HttpMethod::Patch,
        Verb::Delete => HttpMethod::Delete,
    }
}

/// Every error code a route can produce: the ones every route shares, the ones
/// its shape implies, and the ones its entry lists. `None` for a test-only
/// route, which has no documentation.
pub(crate) fn documented_codes(route: &Route) -> Option<BTreeSet<&'static str>> {
    let doc = route.doc()?;
    let mut codes = BTreeSet::from([
        "control-plane.method_not_allowed",
        "control-plane.internal",
        "control-plane.timeout",
    ]);
    if doc.request.is_some() {
        codes.insert("control-plane.payload_too_large");
    }
    if route.path.contains('{') {
        codes.insert("control-plane.invalid_request");
    }
    match route.access {
        Access::Public => {}
        Access::Scoped(_) => {
            codes.extend([
                "identity.unauthenticated",
                "identity.forbidden",
                "control-plane.rate_limited",
            ]);
        }
        // Internal routes authenticate by a binary secret check: a bad or
        // missing credential is `unauthenticated`. There is no scope to lack
        // (no `forbidden`) and no per-token limiter on this path (no
        // `rate_limited`).
        Access::Internal => {
            codes.insert("identity.unauthenticated");
        }
        Access::Session => {
            codes.insert("identity.unauthenticated");
        }
        Access::SessionOptional => {}
    }
    // The same-origin check the route table puts on every cookie-authenticated
    // state-changing route (`http::require_same_origin`).
    if route.access.uses_session_cookie() && route.verb.mutates() {
        codes.insert("identity.forbidden");
    }
    codes.extend(doc.errors.iter().copied());
    Some(codes)
}

/// Whether `code` is covered by a documented set, reading `bundle.*` as the
/// whole delegated family.
#[cfg(test)]
pub(crate) fn covers(documented: &BTreeSet<&'static str>, code: &str) -> bool {
    documented.contains(code) || (code.starts_with("bundle.") && documented.contains(BUNDLE_CODES))
}

/// Status, meaning and hint for a documented code.
fn describe(
    route: &'static str,
    code: &'static str,
) -> Result<(u16, &'static str, &'static str), SpecError> {
    if code == BUNDLE_CODES {
        return Ok((400, DELEGATED_MEANING, DELEGATED_HINT));
    }
    CATALOGUE
        .iter()
        .find(|entry| entry.code == code)
        .map(|entry| (entry.status, entry.meaning, entry.hint))
        .ok_or(SpecError::UnknownCode { route, code })
}

/// The envelope a caller actually receives for `code`, serialised.
fn example_envelope(code: &'static str) -> Result<Value, SpecError> {
    let id = RequestId::sanitize(EXAMPLE_REQUEST_ID).ok_or(SpecError::ExampleRequestId)?;
    let error = if code == BUNDLE_CODES {
        bundle_sample()
    } else {
        owned_samples()
            .into_iter()
            .find(|error| error.code() == code)
            .ok_or(SpecError::NoSample(code))?
    };
    Ok(serde_json::to_value(Envelope::new(&error, &id))?)
}

/// A header an error response carries, by status.
fn error_header(status: u16) -> Option<(&'static str, &'static str)> {
    match status {
        401 => Some(("WWW-Authenticate", "Always `Bearer`.")),
        405 => Some(("Allow", "The methods this path accepts.")),
        429 => Some((
            "Retry-After",
            "Whole seconds to wait before retrying. Never 0.",
        )),
        _ => None,
    }
}

type Components = BTreeMap<String, RefOr<Schema>>;

fn content(body: &Body, components: &mut Components) -> Result<Content, SpecError> {
    let schema = match body.schema {
        SchemaSource::Component(source) => {
            let (name, schema, referenced) = source();
            let reference = RefOr::Ref(Ref::from_schema_name(name.clone()));
            components.insert(name, schema);
            components.extend(referenced);
            reference
        }
        SchemaSource::Inline(source) => RefOr::T(source()),
    };
    let mut builder = ContentBuilder::new().schema(Some(schema));
    if let Some(example) = body.example {
        builder = builder.example(Some(example()?));
    }
    Ok(builder.build())
}

/// The whole document, built from the production route table.
///
/// # Errors
///
/// When a route's documentation is inconsistent with its path, names a code no
/// catalogue declares, or an example fails to serialise. The tests build this,
/// so each of these fails the gate rather than reaching a caller.
pub fn document() -> Result<OpenApi, SpecError> {
    let mut paths = Paths::new();
    let mut components = Components::new();
    let mut produced: BTreeSet<&'static str> = BTreeSet::new();

    for route in production_routes() {
        // Internal routes are served from the same table (walked by the probe,
        // required to carry a Doc) but are not part of the public API surface,
        // so they never appear in the rendered document. See `Access::Internal`.
        if matches!(route.access, Access::Internal) {
            continue;
        }
        let doc = route.doc().ok_or(SpecError::Undocumented(route.path))?;
        let codes = documented_codes(&route).ok_or(SpecError::Undocumented(route.path))?;
        produced.extend(codes.iter().copied());

        let authentication = match route.access {
            Access::Public => "**Authentication:** none.".to_owned(),
            Access::Scoped(scope) => format!(
                "**Authentication:** a bearer token carrying the `{}` scope.",
                scope.as_str()
            ),
            Access::Session => SESSION_AUTHENTICATION.to_owned(),
            Access::SessionOptional => {
                "**Authentication:** none required; the session cookie is read if sent. \
                 Must come from the control plane's own origin."
                    .to_owned()
            }
            // Skipped above: internal routes are never rendered.
            Access::Internal => unreachable!("internal routes are not rendered"),
        };
        let mut operation = OperationBuilder::new()
            .operation_id(Some(doc.operation_id))
            .summary(Some(doc.summary))
            .description(Some(format!("{}\n\n{authentication}", doc.description)));

        let names = path_params(route.path);
        for name in &names {
            let (_, text) = doc
                .params
                .iter()
                .find(|(described, _)| described == name)
                .ok_or_else(|| SpecError::UndescribedParameter {
                    route: route.path,
                    name: (*name).to_owned(),
                })?;
            operation = operation.parameter(
                ParameterBuilder::new()
                    .name(*name)
                    .parameter_in(ParameterIn::Path)
                    .required(Required::True)
                    .description(Some(*text))
                    .schema(Some(uuid_schema()))
                    .build(),
            );
        }
        if let Some((stray, _)) = doc.params.iter().find(|(name, _)| !names.contains(name)) {
            return Err(SpecError::StrayParameter {
                route: route.path,
                name: stray,
            });
        }

        operation = match route.access {
            Access::Public => operation.securities(Some(Vec::<SecurityRequirement>::new())),
            Access::Scoped(scope) => {
                operation.security(SecurityRequirement::new(SECURITY_SCHEME, [scope.as_str()]))
            }
            Access::Session => {
                operation.security(SecurityRequirement::new(COOKIE_SCHEME, Vec::<&str>::new()))
            }
            Access::SessionOptional => {
                operation.securities(Some(Vec::<SecurityRequirement>::new()))
            }
            // Skipped above: internal routes are never rendered.
            Access::Internal => unreachable!("internal routes are not rendered"),
        };

        if let Some(body) = &doc.request {
            operation = operation.request_body(Some(
                RequestBodyBuilder::new()
                    .description(Some(body.description))
                    .required(Some(Required::True))
                    .content(body.content_type, content(body, &mut components)?)
                    .build(),
            ));
        }

        for success in &doc.success {
            let mut response = ResponseBuilder::new().description(success.description);
            if let Some(body) = &success.body {
                response = response.content(body.content_type, content(body, &mut components)?);
            }
            operation = operation.response(success.status.as_u16().to_string(), response.build());
        }

        let mut by_status: BTreeMap<u16, Vec<&'static str>> = BTreeMap::new();
        for &code in &codes {
            let (status, _, _) = describe(route.path, code)?;
            by_status.entry(status).or_default().push(code);
        }
        for (status, codes) in by_status {
            let mut lines = Vec::with_capacity(codes.len());
            let mut examples = Vec::with_capacity(codes.len());
            for code in codes {
                let (_, meaning, hint) = describe(route.path, code)?;
                lines.push(format!("- `{code}`: {meaning} **What to do:** {hint}"));
                examples.push((
                    code,
                    ExampleBuilder::new()
                        .summary(code)
                        .description(format!("{meaning} What to do: {hint}"))
                        .value(Some(example_envelope(code)?))
                        .build(),
                ));
            }
            let body = ContentBuilder::new()
                .schema(Some(RefOr::Ref(Ref::from_schema_name(ENVELOPE))))
                .examples_from_iter(examples)
                .build();
            let mut response = ResponseBuilder::new()
                .description(lines.join("\n"))
                .content(JSON, body);
            if let Some((name, text)) = error_header(status) {
                response = response.header(
                    name,
                    HeaderBuilder::new()
                        .schema(string_schema())
                        .description(Some(text))
                        .build(),
                );
            }
            operation = operation.response(status.to_string(), response.build());
        }

        paths.add_path_operation(route.path, vec![http_method(route.verb)], operation.build());
    }

    let components = components.into_iter().fold(
        ComponentsBuilder::new()
            .schema(ENVELOPE, envelope_schema())
            .security_scheme(
                SECURITY_SCHEME,
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("clwd_tok_")
                        .description(Some(AUTHENTICATION))
                        .build(),
                ),
            )
            .security_scheme(
                COOKIE_SCHEME,
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                    crate::session::COOKIE_NAME,
                    SESSION_AUTHENTICATION,
                ))),
            ),
        |builder, (name, schema)| builder.schema(name, schema),
    );

    Ok(OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("clwd platform API")
                .version(env!("CARGO_PKG_VERSION"))
                .description(Some(overview(&produced)))
                .build(),
        )
        .paths(paths)
        .components(Some(components.build()))
        .build())
}

/// The document's introduction: how to authenticate, and the whole error
/// catalogue with meaning and recovery for each code.
fn overview(produced: &BTreeSet<&'static str>) -> String {
    let mut text = format!(
        "The control plane API. Every operation lists the scope it needs and every error it can return, with what each error means and what to do about it.\n\n\
         ## Authentication\n\n{AUTHENTICATION}\n\n\
         ## Errors\n\n\
         Every 4xx and 5xx response carries the `Envelope` body. Branch on `code`, which is stable; `retryable` says whether the same request could succeed later.\n\n\
         | Code | Status | Retryable | Meaning | What to do |\n|---|---|---|---|---|\n"
    );
    for entry in CATALOGUE {
        text.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            entry.code,
            entry.status,
            if entry.retryable { "yes" } else { "no" },
            entry.meaning,
            entry.hint
        ));
    }
    text.push_str(&format!(
        "| `bundle.*` | 400 | per code | {DELEGATED_MEANING} | See the bundle format's code table: {BUNDLE_TABLE} |\n"
    ));
    let unproduced: Vec<String> = CATALOGUE
        .iter()
        .filter(|entry| !produced.contains(entry.code))
        .map(|entry| format!("`{}`", entry.code))
        .collect();
    if !unproduced.is_empty() {
        text.push_str(&format!(
            "\nNo operation produces {} today; they are listed so the catalogue is complete.\n",
            unproduced.join(" or ")
        ));
    }
    text
}

/// The document as JSON, exactly as committed: pretty-printed, object keys in
/// sorted order, one trailing newline.
///
/// # Why the keys are sorted here rather than left to the serialiser
///
/// Whether `serde_json` keeps insertion order or sorts depends on its
/// `preserve_order` feature, and features are unified across whatever is being
/// built together. `cedar-policy-core`, reached through the `identity` crate,
/// enables it — so a workspace build and a `-p control-plane` build produced the
/// same document with different key order, and the committed bytes depended on
/// which command made them. Sorting while serialising makes the bytes a function
/// of the document alone.
///
/// # Errors
///
/// As [`document`], or if serialisation fails.
pub fn json() -> Result<String, SpecError> {
    let value = serde_json::to_value(document()?)?;
    let mut text = serde_json::to_string_pretty(&Sorted(&value))?;
    text.push('\n');
    Ok(text)
}

/// Serialises a JSON value with every object's keys in sorted order, whatever
/// order its maps hold them in.
struct Sorted<'a>(&'a Value);

impl serde::Serialize for Sorted<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        match self.0 {
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
                let mut out = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    out.serialize_entry(key, &Sorted(value))?;
                }
                out.end()
            }
            Value::Array(items) => serializer.collect_seq(items.iter().map(Sorted)),
            other => other.serialize(serializer),
        }
    }
}

/// `GET /openapi.json` — public.
///
/// The committed file, not a document built per request: it changes at deploy
/// time, so there is nothing to compute, and serving the checked bytes is what
/// makes "served" and "checked" the same thing by construction.
pub(crate) async fn serve() -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(JSON)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        COMMITTED,
    )
        .into_response()
}

/// The documentation for `GET /openapi.json`.
pub(crate) fn doc() -> Doc {
    Doc {
        operation_id: "getOpenApiDocument",
        summary: "This document",
        description: "The OpenAPI document describing every operation, the scope each needs, and every error each can return. Public, so a caller can learn how to authenticate before it holds a token.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::OK,
            description: "This document.",
            body: Some(Body::openapi_document("An OpenAPI 3.1 document.")),
        }],
        errors: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body as HttpBody;
    use axum::extract::Request;
    use serde_json::json;
    use std::time::Duration;
    use tower::ServiceExt as _;

    const OPENAPI_31_SCHEMA: &str = include_str!("../openapi-3.1-schema.json");
    const OPERATION_METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

    fn committed() -> Value {
        serde_json::from_str(COMMITTED).expect("the committed document is JSON")
    }

    fn method(verb: Verb) -> &'static str {
        match verb {
            Verb::Get => "get",
            Verb::Post => "post",
            Verb::Put => "put",
            Verb::Patch => "patch",
            Verb::Delete => "delete",
        }
    }

    /// A JSON pointer segment, escaped.
    fn segment(raw: &str) -> String {
        raw.replace('~', "~0").replace('/', "~1")
    }

    /// Every `$ref` value in a JSON value.
    fn refs(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    match (key.as_str(), inner) {
                        ("$ref", Value::String(target)) => out.push(target.clone()),
                        _ => refs(inner, out),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|inner| refs(inner, out)),
            _ => {}
        }
    }

    /// The committed file is what the route table produces today. A stale file
    /// is the one way the served document could describe an API that no longer
    /// exists.
    #[test]
    fn the_committed_document_is_current() {
        let generated = json().expect("the document generates");
        assert!(
            generated == COMMITTED,
            "crates/control-plane/openapi.json is stale: run `just openapi` and commit the result"
        );
    }

    /// Every production route appears in the committed document, and every
    /// operation in it has a route. Read from the committed file rather than the
    /// generator, so it counts what a caller is actually served.
    #[test]
    fn every_production_route_is_documented() {
        let spec = committed();
        let routes = production_routes();
        let table: BTreeSet<(String, &str)> = routes
            .iter()
            .map(|route| (route.path.to_owned(), method(route.verb)))
            .collect();

        // The public API surface: internal routes are served from the same
        // table but are deliberately absent from the document, so they are not
        // expected in it. Counting all routes here would fail on every internal
        // route; counting them as documented if they appeared would hide an
        // internal route leaking into the public spec, which this must catch.
        let public = routes
            .iter()
            .filter(|route| !matches!(route.access, Access::Internal))
            .count();

        let documented = routes
            .iter()
            .filter(|route| {
                spec.pointer(&format!(
                    "/paths/{}/{}",
                    segment(route.path),
                    method(route.verb)
                ))
                .is_some()
            })
            .count();

        let mut stray = Vec::new();
        for (path, item) in spec["paths"].as_object().into_iter().flatten() {
            for (verb, _) in item.as_object().into_iter().flatten() {
                if OPERATION_METHODS.contains(&verb.as_str())
                    && !table.contains(&(path.clone(), verb.as_str()))
                {
                    stray.push(format!("{verb} {path}"));
                }
            }
        }

        println!(
            "routes documented: {documented} of {public} public ({} in table); operations without a route: {}",
            routes.len(),
            stray.len()
        );
        assert_eq!(
            documented, public,
            "a public production route is missing from the committed OpenAPI document, \
             or an internal route leaked into it"
        );
        assert!(
            stray.is_empty(),
            "the committed OpenAPI document describes operations no route serves: {stray:?}"
        );
    }

    /// The document is valid OpenAPI 3.1, and every `$ref` in it resolves.
    #[test]
    fn the_document_validates_against_the_openapi_31_schema() {
        let schema: Value =
            serde_json::from_str(OPENAPI_31_SCHEMA).expect("the vendored schema is JSON");
        let validator =
            jsonschema::validator_for(&schema).expect("the OpenAPI 3.1 schema compiles");

        // Positive control: the validator rejects a document that is not one.
        assert!(
            !validator.is_valid(&json!({"openapi": "3.1.0"})),
            "the validator accepted a document with no info, so it validates nothing"
        );

        let spec = committed();
        let violations: Vec<String> = validator
            .iter_errors(&spec)
            .map(|error| format!("{error} at {}", error.instance_path()))
            .collect();

        let mut all = Vec::new();
        refs(&spec, &mut all);
        let unresolved: Vec<&String> = all
            .iter()
            .filter(|target| {
                target
                    .strip_prefix('#')
                    .is_none_or(|pointer| spec.pointer(pointer).is_none())
            })
            .collect();

        println!(
            "openapi document: {} schema violations; {} $refs, {} unresolved",
            violations.len(),
            all.len(),
            unresolved.len()
        );
        assert!(violations.is_empty(), "{violations:#?}");
        assert!(
            !all.is_empty(),
            "no $ref at all, so resolution checked nothing"
        );
        assert!(unresolved.is_empty(), "{unresolved:#?}");
    }

    /// Every example in the document validates against the schema beside it.
    /// The examples are real serialised values, so this is what catches the
    /// hand-written envelope schema drifting from the envelope.
    #[test]
    fn every_example_validates_against_its_schema() {
        let spec = committed();

        // A schema at a pointer in the document, compiled with the whole
        // document as its base so component `$ref`s resolve.
        let validator_at = |pointer: &str| {
            let mut root = spec.clone();
            let fragment = pointer.replace('{', "%7B").replace('}', "%7D");
            root["$ref"] = json!(format!("#{fragment}"));
            jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .build(&root)
                .unwrap_or_else(|error| panic!("the schema at {pointer} compiles: {error}"))
        };

        // Positive control: a wrong example is rejected.
        assert!(
            !validator_at("/components/schemas/Envelope").is_valid(&json!({"code": 1})),
            "the envelope schema accepted a non-envelope, so this test validates nothing"
        );

        let mut checked = 0;
        let mut failures = Vec::new();
        for (path, item) in spec["paths"].as_object().into_iter().flatten() {
            for (verb, operation) in item.as_object().into_iter().flatten() {
                if !OPERATION_METHODS.contains(&verb.as_str()) {
                    continue;
                }
                let base = format!("/paths/{}/{verb}", segment(path));
                let mut media = Vec::new();
                if let Some(content) = operation.pointer("/requestBody/content") {
                    media.push((format!("{base}/requestBody/content"), content));
                }
                for (status, response) in operation["responses"].as_object().into_iter().flatten() {
                    if let Some(content) = response.get("content") {
                        media.push((format!("{base}/responses/{status}/content"), content));
                    }
                }
                for (pointer, content) in media {
                    for (content_type, entry) in content.as_object().into_iter().flatten() {
                        let schema = format!("{pointer}/{}/schema", segment(content_type));
                        let mut examples: Vec<&Value> = entry.get("example").into_iter().collect();
                        for (_, named) in entry["examples"].as_object().into_iter().flatten() {
                            examples.extend(named.get("value"));
                        }
                        if examples.is_empty() {
                            continue;
                        }
                        let validator = validator_at(&schema);
                        for example in examples {
                            checked += 1;
                            for error in validator.iter_errors(example) {
                                failures.push(format!("{schema}: {error}"));
                            }
                        }
                    }
                }
            }
        }

        println!("openapi examples validated against their schemas: {checked}");
        assert!(checked > 0, "no examples found, so none were checked");
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// Every owned code reaches the document with its meaning and its hint.
    #[test]
    fn every_error_code_is_documented_with_meaning_and_hint() {
        let spec = committed();
        let description = spec["info"]["description"].as_str().unwrap_or_default();
        let complete = CATALOGUE
            .iter()
            .filter(|entry| {
                description.contains(entry.code)
                    && description.contains(entry.meaning)
                    && description.contains(entry.hint)
            })
            .count();
        println!(
            "error codes documented with meaning and hint: {complete} of {}",
            CATALOGUE.len()
        );
        assert_eq!(complete, CATALOGUE.len());
        assert!(
            description.contains(BUNDLE_TABLE),
            "the bundle.* family is not linked"
        );
    }

    /// The token request example is a request the route accepts.
    #[test]
    fn request_examples_deserialize_into_the_request_types() {
        let example = crate::auth::issue_request_example().expect("serialises");
        let parsed: Result<crate::auth::IssueRequest, _> = serde_json::from_value(example);
        assert!(
            parsed.is_ok(),
            "the documented request is one the route would reject"
        );
    }

    /// The served document is the committed file, byte for byte, with no token.
    #[tokio::test]
    async fn the_served_document_is_the_committed_one() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("a lazy pool connects to nothing");
        let operator = opendal::Operator::new(opendal::services::Memory::default())
            .expect("an in-memory operator");
        let state = crate::http::AppState::new(pool, builder::ArtifactStore::new(operator));

        let request = Request::builder()
            .uri("/openapi.json")
            .body(HttpBody::empty())
            .expect("a valid request");
        let response = crate::http::router(state)
            .oneshot(request)
            .await
            .expect("the router answers");

        assert_eq!(response.status(), StatusCode::OK, "public: no token needed");
        assert_eq!(response.headers()[header::CONTENT_TYPE], JSON);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .expect("body");
        assert!(
            &bytes[..] == COMMITTED.as_bytes(),
            "the served bytes are not the committed file"
        );
    }
}
