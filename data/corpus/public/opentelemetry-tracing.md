# OpenTelemetry Tracing Standards

Owner: Observability

## Instrumentation

Services MUST use the OpenTelemetry SDK and propagate W3C `traceparent`
headers across HTTP and gRPC boundaries. Background workers must continue
traces from message headers.

## Sampling

Production uses a head-based sampler at 10% with a tail-based collector that
retains all errors and all traces slower than two seconds. Sampling decisions
must be recorded as span attributes.

## Resource attributes

Every span must include `service.name`, `deployment.environment`, and
`service.version`. High-cardinality values such as user IDs must not be used
as metric labels; attach them to spans instead.

## Data handling

Trace attributes are reviewed quarterly for sensitive data. PII must be
redacted at the SDK boundary before export.
